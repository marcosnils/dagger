package schema

import (
	"github.com/dagger/dagger/core"
	"github.com/dagger/dagger/router"
	"github.com/moby/buildkit/client/llb"
)

var _ router.ExecutableSchema = &httpSchema{}

type httpSchema struct {
	*baseSchema
}

func (s *httpSchema) Name() string {
	return "http"
}

func (s *httpSchema) Schema() string {
	return HTTP
}

func (s *httpSchema) Resolvers() router.Resolvers {
	return router.Resolvers{
		"Query": router.ObjectResolver{
			"http": router.ToResolver(s.http),
		},
	}
}

func (s *httpSchema) Dependencies() []router.ExecutableSchema {
	return nil
}

type httpArgs struct {
	URL string `json:"url"`

	ServiceDependency *core.ContainerID `json:"serviceDependency"`
}

func (s *httpSchema) http(ctx *router.Context, parent *core.Query, args httpArgs) (*core.File, error) {
	pipeline := core.PipelinePath{}
	if parent != nil {
		pipeline = parent.Context.Pipeline
	}

	st := llb.HTTP(args.URL, llb.Filename("contents"), pipeline.LLBOpt())

	svcs := []core.ContainerID{}
	if args.ServiceDependency != nil {
		svcs = append(svcs, *args.ServiceDependency)
	}

	f, err := core.NewFile(ctx, st, "contents", pipeline, s.platform, svcs...)
	if err != nil {
		return nil, err
	}
	return f, nil
}
