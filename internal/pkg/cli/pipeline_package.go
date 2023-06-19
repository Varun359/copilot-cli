package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	deploypkg "github.com/aws/copilot-cli/internal/pkg/deploy"
)

type packagePipelineVars struct {
	name    string
	appName string
}

type packagePipelineOpts struct {
	packagePipelineVars
	deployPipelineOpts

	templateWriter io.WriteCloser
}

func newPackagePieplineOpts(vars packagePipelineVars) (*packagePipelineOpts, error) {
	opts := &packagePipelineOpts{
		templateWriter: os.Stdout,
	}
	return opts, nil
}

func (o *packagePipelineOpts) Execute() error {

	// Read pipeline manifest.
	pipeline, err := o.getPipelineMft()
	if err != nil {
		return err
	}

	// If the source has an existing connection, get the correlating ConnectionARN.
	connection, ok := pipeline.Source.Properties["connection_name"]
	if ok {
		arn, err := o.codestar.GetConnectionARN((connection).(string))
		if err != nil {
			return fmt.Errorf("get connection ARN: %w", err)
		}
		pipeline.Source.Properties["connection_arn"] = arn
	}

	source, shouldPrompt, err := deploypkg.PipelineSourceFromManifest(pipeline.Source)
	if err != nil {
		return fmt.Errorf("read source from manifest: %w", err)
	}
	o.shouldPromptUpdateConnection = shouldPrompt

	// Convert full manifest path to relative path from workspace root.
	relPath, err := o.ws.Rel(o.pipeline.Path)
	if err != nil {
		return err
	}

	// Convert environments to deployment stages.
	stages, err := o.convertStages(pipeline.Stages)
	if err != nil {
		return fmt.Errorf("convert environments to deployment stage: %w", err)
	}

	// Get cross-regional resources.
	artifactBuckets, err := o.getArtifactBuckets()
	if err != nil {
		return fmt.Errorf("get cross-regional resources: %w", err)
	}

	isLegacy, err := o.isLegacy(pipeline.Name)
	if err != nil {
		return err
	}
	var build deploypkg.Build
	if err = build.Init(pipeline.Build, filepath.Dir(relPath)); err != nil {
		return err
	}
	deployPipelineInput := &deploypkg.CreatePipelineInput{
		AppName:             o.appName,
		Name:                o.name,
		IsLegacy:            isLegacy,
		Source:              source,
		Build:               &build,
		Stages:              stages,
		ArtifactBuckets:     artifactBuckets,
		AdditionalTags:      o.app.Tags,
		PermissionsBoundary: o.app.PermissionsBoundary,
	}
}
