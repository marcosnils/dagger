package core

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	doublestar "github.com/bmatcuk/doublestar/v4"
	"github.com/dagger/dagger/dagql"
	"github.com/dagger/dagger/dagql/call"
	"github.com/vektah/gqlparser/v2/ast"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/sync/errgroup"
)

// NetworkProtocol is a GraphQL enum type.
type CheckResult string

var CheckResults = dagql.NewEnum[CheckResult]()

var (
	CheckResultPassed  = CheckResults.Register("PASSED")
	CheckResultFailed  = CheckResults.Register("FAILED")
	CheckResultSkipped = CheckResults.Register("SKIPPED")
)

func (r CheckResult) Type() *ast.Type {
	return &ast.Type{
		NamedType: "CheckResult",
		NonNull:   true,
	}
}

func (r CheckResult) TypeDescription() string {
	return "The result of a check."
}

func (r CheckResult) Decoder() dagql.InputDecoder {
	return CheckResults
}

func (r CheckResult) ToLiteral() call.Literal {
	return CheckResults.Literal(r)
}

// Check represents a validation check with its result
type Check struct {
	Name         string      `field:"true" doc:"The name of the check"`
	Context      string      `field:"true" doc:"The context of the check. Can be a remote git address, or a local path"`
	Description  string      `field:"true" doc:"The description of the check"`
	Executed     bool        `field:"true" doc:"Whether the check was executed"`
	Result       CheckResult `field:"true" doc:"Whether the check passed, failed or was skipped"`
	Message      string      `field:"true" doc:"A message emitted when running the check"`
	ModuleName   string      `field:"true"`
	FunctionName string      `field:"true"`
}

func (c *Check) WithResult(result CheckResult) *Check {
	c.Result = result
	return c
}

func (*Check) Type() *ast.Type {
	return &ast.Type{
		NamedType: "Check",
		NonNull:   true,
	}
}

type CheckGroup struct {
	// FIXME: filtering
	Checks []*Check `json:"checks"`
}

func (*CheckGroup) Type() *ast.Type {
	return &ast.Type{
		NamedType: "CheckGroup",
		NonNull:   true,
	}
}

func CurrentChecks(ctx context.Context, include []string) (*CheckGroup, error) {
	// Get the modules being served to the current client
	q, err := CurrentQuery(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current query: %w", err)
	}
	deps, err := q.CurrentServedDeps(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get served dependencies: %w", err)
	}
	// Collect all check functions from all modules
	var report CheckGroup

	// Iterate through all modules
	for _, mod := range deps.Mods {
		// Type assert to *Module to access ObjectDefs
		module, ok := mod.(*Module)
		if !ok {
			// Skip non-user modules (e.g., core modules)
			continue
		}
		// FIXME: skip non-local dependencies
		_, modSpan := Tracer(ctx).Start(ctx, fmt.Sprintf("[checks] mod=%q", module.OriginalName))
		modSpan.End()
		// Find the main object for this module
		// The main object is the one whose OriginalName matches the module's OriginalName
		var mainObject *ObjectTypeDef
		for _, objDef := range module.ObjectDefs {
			if objDef.AsObject.Valid {
				obj := objDef.AsObject.Value

				// Check if this is the main object by comparing normalized names
				if gqlFieldName(obj.Name) == gqlFieldName(module.Name()) {
					mainObject = obj
					break
				}
			}
		}
		// If no main object found, skip this module
		if mainObject == nil {
			// FIXME: also support checks on non-main objects
			// (if they are reachable)
			// This is required to reach all checks in our CI monolith;
			// and will be required for blueprint support
			// NOTE: also remove support for dependencies? How?
			continue
		}
		// Search for functions starting with "Check" in the main object
		for _, fn := range mainObject.Functions {
			checkName, isCheck, _ := functionIsCheck(fn)
			if !isCheck {
				continue
			}
			check := &Check{
				Name:         checkName,
				Description:  fn.Description,
				ModuleName:   module.Name(),
				FunctionName: fn.Name,
			}
			if module.Source.Valid {
				src := module.Source.Value.Self()
				switch src.Kind {
				case ModuleSourceKindLocal:
					check.Context = src.SourceRootSubpath
				case ModuleSourceKindGit:
					check.Context = src.SourceRootSubpath
				}
			}
			if included, err := check.Match(include); err != nil {
				return nil, err
			} else if included {
				report.Checks = append(report.Checks, check)
			}
		}
	}
	return &report, nil
}

func (c *Check) Match(include []string) (bool, error) {
	if len(include) == 0 {
		return true, nil
	}
	fullName := c.FullName()
	for _, pattern := range include {
		matched, err := doublestar.PathMatch(pattern, fullName)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func (r *CheckGroup) List(ctx context.Context) ([]*Check, error) {
	return r.Checks, nil
}

// Run all the checks in the group
func (r *CheckGroup) Run(ctx context.Context) (*CheckGroup, error) {
	r = r.Clone()
	eg := errgroup.Group{}
	for i, check := range r.Checks {
		i := i
		eg.Go(func() (rerr error) {
			ctx, span := Tracer(ctx).Start(ctx, check.FullName())
			defer func() {
				if rerr != nil {
					span.SetStatus(codes.Error, rerr.Error())
				}
				span.End()
			}()
			result, message, err := check.Run(ctx)
			if err != nil {
				return err
			}
			r.Checks[i].Result = result
			r.Checks[i].Message = message
			r.Checks[i].Executed = true
			return nil
		})
	}
	err := eg.Wait()
	return r, err
}

func (c *Check) ResultEmoji() string {
	switch c.Result {
	case CheckResultFailed:
		return "🔴"
	case CheckResultPassed:
		return "🟢"
	case CheckResultSkipped:
		return "⏭️"
	}
	return ""
}

func (r *CheckGroup) Report(ctx context.Context) (*File, error) {
	headers := []string{"check", "description", "success", "message"}
	rows := [][]string{}
	for _, check := range r.Checks {
		rows = append(rows, []string{
			check.FullName(),
			check.Description,
			check.ResultEmoji(),
			check.Message,
		})
	}
	contents := []byte(markdownTable(headers, rows...))
	q, err := CurrentQuery(ctx)
	if err != nil {
		return nil, err
	}
	return NewFileWithContents(ctx, "checks.md", contents, fs.FileMode(0644), nil, q.Platform())
}

func markdownTable(headers []string, rows ...[]string) string {
	var sb strings.Builder
	sb.WriteString("| " + strings.Join(headers, " | ") + " |\n")
	for range headers {
		sb.WriteString("| -- ")
	}
	sb.WriteString("|\n")
	for _, row := range rows {
		sb.WriteString("|" + strings.Join(row, " | ") + " |\n")
	}
	return sb.String()
}

func functionIsCheck(fn *Function) (string, bool, string) {
	// For a function to be considered a check...
	// 1. ...it must return a CheckResult
	if fn.ReturnType.ToType().Name() != "CheckResult" {
		return fn.Name, false, "function %q doesn't return a CheckResult"
	}
	// 2. ...it must have no required arguments
	for _, arg := range fn.Args {
		// NOTE: we count on user defaults already merged in the schema at this point
		// "regular optional" -> ok
		if arg.TypeDef.Optional {
			continue
		}
		// "contextual optional" -> ok
		if arg.DefaultPath != "" {
			continue
		}
		// default value -> ok
		if arg.DefaultValue != nil {
			continue
		}
		return "", false, fmt.Sprintf("function %q has a non-optional argument %q", fn.Name, arg.Name)
	}
	return fn.Name, true, ""
}

func (r *CheckGroup) Clone() *CheckGroup {
	cp := *r
	cp.Checks = slices.Clone(cp.Checks)
	return &cp
}

func (c *Check) FullName() string {
	if c.Name == "" {
		return c.Context
	}
	if slices.Contains([]string{"", ".", "/"}, c.Context) {
		return c.Name
	}
	return c.Context + "/" + c.Name
}

// Run executes the check and returns the result
func (c *Check) Run(ctx context.Context) (CheckResult, string, error) {
	q, err := CurrentQuery(ctx)
	if err != nil {
		return CheckResultFailed, "", err
	}
	deps, err := q.CurrentServedDeps(ctx)
	if err != nil {
		return CheckResultFailed, "", err
	}
	srv, err := deps.Schema(ctx)
	if err != nil {
		return CheckResultFailed, "", err
	}
	var result CheckResult
	err = srv.Select(ctx, srv.Root(), &result,
		dagql.Selector{Field: gqlFieldName(c.ModuleName)},
		dagql.Selector{Field: gqlFieldName(c.FunctionName)},
	)
	if err != nil {
		// FIXME: can't differentiate real errors from failed checks
		return CheckResultFailed, err.Error(), nil //nolint:nilerr
	}
	return result, "", nil
}
