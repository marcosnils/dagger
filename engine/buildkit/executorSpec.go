package buildkit

import (
	"fmt"
	"os"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	DaggerServerIDEnv      = "_DAGGER_SERVER_ID"
	DaggerCallDigestEnv    = "_DAGGER_CALL_DIGEST"
	DaggerEngineVersionEnv = "_DAGGER_ENGINE_VERSION"
)

// some envs that are used to scope cache but not needed at runtime
var removeEnvs = map[string]struct{}{
	DaggerCallDigestEnv:    {},
	DaggerEngineVersionEnv: {},
}

func (w *Worker) applySpecCustomizations(spec *specs.Spec) error {
	if err := w.updateEnvs(spec); err != nil {
		return err
	}

	return nil
}

func (w *Worker) updateEnvs(spec *specs.Spec) error {
	filteredEnvs := make([]string, 0, len(spec.Process.Env))
	for _, env := range spec.Process.Env {
		k, _, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		if _, ok := removeEnvs[k]; ok {
			continue
		}
		filteredEnvs = append(filteredEnvs, env)
	}
	spec.Process.Env = filteredEnvs

	origEnvMap := make(map[string]string)
	for _, env := range spec.Process.Env {
		k, v, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		origEnvMap[k] = v
	}

	for _, upperProxyEnvName := range []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"FTP_PROXY",
		"NO_PROXY",
		"ALL_PROXY",
	} {
		upperProxyVal, upperSet := origEnvMap[upperProxyEnvName]

		lowerProxyEnvName := strings.ToLower(upperProxyEnvName)
		lowerProxyVal, lowerSet := origEnvMap[lowerProxyEnvName]

		// try to set both upper and lower case proxy env vars, some programs
		// only respect one or the other
		switch {
		case upperSet && lowerSet:
			// both were already set explicitly by the user, don't overwrite
			continue
		case upperSet:
			// upper case was set, set lower case to the same value
			spec.Process.Env = append(spec.Process.Env, lowerProxyEnvName+"="+upperProxyVal)
		case lowerSet:
			// lower case was set, set upper case to the same value
			spec.Process.Env = append(spec.Process.Env, upperProxyEnvName+"="+lowerProxyVal)
		default:
			// neither was set by the user, check if the engine itself has the upper case
			// set and pass that through to the container in both cases if so
			val, ok := os.LookupEnv(upperProxyEnvName)
			if ok {
				spec.Process.Env = append(spec.Process.Env, upperProxyEnvName+"="+val, lowerProxyEnvName+"="+val)
			}
		}
	}

	if w.execMD == nil {
		return nil
	}

	spec.Process.Env = append(spec.Process.Env, DaggerServerIDEnv+"="+w.execMD.ServerID)
	spec.Process.Env = append(spec.Process.Env, w.execMD.OTELEnvs...)
	if w.execMD.ClientID != "" {
		spec.Process.Env = append(spec.Process.Env, "_DAGGER_NESTED_CLIENT_ID="+w.execMD.ClientID)
	}

	const systemEnvPrefix = "_DAGGER_ENGINE_SYSTEMENV_"
	for _, systemEnvName := range w.execMD.SystemEnvNames {
		if _, ok := origEnvMap[systemEnvName]; ok {
			// don't overwrite explicit user-provided values
			continue
		}
		systemVal, ok := os.LookupEnv(systemEnvPrefix + systemEnvName)
		if ok {
			spec.Process.Env = append(spec.Process.Env, systemEnvName+"="+systemVal)
		}
	}

	return nil
}

func (w *Worker) enableGPU(spec *specs.Spec) error {
	if w.execMD == nil {
		return nil
	}
	if len(w.execMD.EnabledGPUs) == 0 {
		return nil
	}

	if spec.Hooks == nil {
		spec.Hooks = &specs.Hooks{}
	}
	spec.Hooks.Prestart = append(spec.Hooks.Prestart, specs.Hook{
		Args: []string{
			"nvidia-container-runtime-hook",
			"prestart",
		},
		Path: "/usr/bin/nvidia-container-runtime-hook",
	})
	spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("NVIDIA_VISIBLE_DEVICES=%s",
		strings.Join(w.execMD.EnabledGPUs, ","),
	))

	return nil
}