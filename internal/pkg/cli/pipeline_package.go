package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	rg "github.com/aws/copilot-cli/internal/pkg/aws/resourcegroups"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/cli/list"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	deploycfn "github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation/stack"
	"github.com/aws/copilot-cli/internal/pkg/manifest"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/term/selector"
	"github.com/aws/copilot-cli/internal/pkg/workspace"
	"github.com/spf13/afero"
)

type packagePipelineVars struct {
	name    string
	appName string
}

type packagePipelineOpts struct {
	packagePipelineVars
	//deployPipelineOpts

	pipelineDeployer                pipelineDeployer
	tmplWriter                      io.WriteCloser
	ws                              wsPipelineReader
	codestar                        codestar
	store                           store
	pipelineStackConfig             func(in *deploy.CreatePipelineInput) pipelineStackConfig
	configureDeployedPipelineLister func() deployedPipelineLister
	newSvcListCmd                   func(io.Writer, string) cmd
	newJobListCmd                   func(io.Writer, string) cmd
	//        wsPipelineSelector

	//catched variables
	pipelineMft *manifest.Pipeline
	// pipeline    *workspace.PipelineManifest
	app       *config.Application
	svcBuffer *bytes.Buffer
	jobBuffer *bytes.Buffer
}

func newPackagePipelineOpts(vars packagePipelineVars) (*packagePipelineOpts, error) {
	defaultSession, err := sessions.ImmutableProvider(sessions.UserAgentExtras("pipeline deploy")).Default()
	if err != nil {
		return nil, fmt.Errorf("default session: %w", err)
	}
	store := config.NewSSMStore(identity.New(defaultSession), ssm.New(defaultSession), aws.StringValue(defaultSession.Config.Region))

	ws, err := workspace.Use(afero.NewOsFs())
	if err != nil {
		return nil, err
	}
	opts := &packagePipelineOpts{
		packagePipelineVars: vars,
		pipelineDeployer:    deploycfn.New(defaultSession, deploycfn.WithProgressTracker(os.Stderr)),
		tmplWriter:          os.Stdout,
		ws:                  ws,
		store:               store,
		pipelineStackConfig: func(in *deploy.CreatePipelineInput) pipelineStackConfig {
			return stack.NewPipelineStackConfig(in)
		},
		newSvcListCmd: func(w io.Writer, appName string) cmd {
			return &listSvcOpts{
				listWkldVars: listWkldVars{
					appName: appName,
				},
				sel: selector.NewAppEnvSelector(prompt.New(), store),
				list: &list.SvcListWriter{
					Ws:    ws,
					Store: store,
					Out:   w,

					ShowLocalSvcs: true,
					OutputJSON:    true,
				},
			}
		},
		newJobListCmd: func(w io.Writer, appName string) cmd {
			return &listJobOpts{
				listWkldVars: listWkldVars{
					appName: appName,
				},
				sel: selector.NewAppEnvSelector(prompt.New(), store),
				list: &list.JobListWriter{
					Ws:    ws,
					Store: store,
					Out:   w,

					ShowLocalJobs: true,
					OutputJSON:    true,
				},
			}
		},
		svcBuffer: &bytes.Buffer{},
		jobBuffer: &bytes.Buffer{},
		// codestar:   cs.New(defaultSession),
	}
	opts.configureDeployedPipelineLister = func() deployedPipelineLister {
		// Initialize the client only after the appName is asked.
		return deploy.NewPipelineStore(rg.New(defaultSession))
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

	source, _, err := deploy.PipelineSourceFromManifest(pipeline.Source)
	if err != nil {
		return fmt.Errorf("read source from manifest: %w", err)
	}
	//o.shouldPromptUpdateConnection = shouldPrompt

	// Convert full manifest path to relative path from workspace root.

	pipelines, err := o.ws.ListPipelines()

	pipeline_path := ""
	for _, pipeline := range pipelines {
		if pipeline.Name == o.name {
			pipeline_path = pipeline.Path
			break
		}
	}
	relPath, err := o.ws.Rel(pipeline_path)
	if err != nil {
		return err
	}

	fmt.Println("The source and the relpath is ", source, relPath)

	//Convert environments to deployment stages.
	stages, err := o.convertStages(pipeline.Stages)
	if err != nil {
		return fmt.Errorf("convert environments to deployment stage: %w", err)
	}

	appConfig, err := o.store.GetApplication(o.appName)
	if err != nil {
		return fmt.Errorf("get application %s configuration: %w", o.appName, err)
	}
	o.app = appConfig

	// Get cross-regional resources.
	artifactBuckets, err := o.getArtifactBuckets()
	if err != nil {
		return fmt.Errorf("get cross-regional resources: %w", err)
	}

	isLegacy, err := o.isLegacy(pipeline.Name)
	if err != nil {
		return err
	}

	var build deploy.Build
	if err = build.Init(pipeline.Build, filepath.Dir(relPath)); err != nil {
		return err
	}
	deployPipelineInput := &deploy.CreatePipelineInput{
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

	tpl, err := o.pipelineStackConfig(deployPipelineInput).Template()
	if err != nil {
		return fmt.Errorf("generate the new template for diff: %w", err)
	}

	fmt.Println("this is the template", tpl)
	if _, err := o.tmplWriter.Write([]byte(tpl)); err != nil {
		return err
	}
	o.tmplWriter.Close()
	return nil
}

func (o *packagePipelineOpts) getPipelineMft() (*manifest.Pipeline, error) {

	pipelines, err := o.ws.ListPipelines()

	pipeline_path := ""
	for _, pipeline := range pipelines {
		if pipeline.Name == o.name {
			pipeline_path = pipeline.Path
			break
		}
	}
	if o.pipelineMft != nil {
		return o.pipelineMft, nil
	}

	fmt.Println("The pipeline path is ", pipeline_path)
	pipelineMft, err := o.ws.ReadPipelineManifest(pipeline_path)
	if err != nil {
		return nil, fmt.Errorf("read pipeline manifest: %w", err)
	}

	if err := pipelineMft.Validate(); err != nil {
		return nil, fmt.Errorf("validate pipeline manifest: %w", err)
	}
	o.pipelineMft = pipelineMft
	return pipelineMft, nil
}

func (o *packagePipelineOpts) isLegacy(inputName string) (bool, error) {
	lister := o.configureDeployedPipelineLister()
	pipelines, err := lister.ListDeployedPipelines(o.appName)
	if err != nil {
		return false, fmt.Errorf("list deployed pipelines for app %s: %w", o.appName, err)
	}
	for _, pipeline := range pipelines {
		if pipeline.ResourceName == inputName {
			// NOTE: this is double insurance. A namespaced pipeline's `ResourceName` wouldn't be equal to
			// `inputName` in the first place, because it would have been namespaced and have random string
			// appended by CFN.
			return pipeline.IsLegacy, nil
		}
	}
	return false, nil
}

func (o *packagePipelineOpts) convertStages(manifestStages []manifest.PipelineStage) ([]deploy.PipelineStage, error) {
	var stages []deploy.PipelineStage
	workloads, err := o.getLocalWorkloads()
	if err != nil {
		return nil, err
	}
	for _, stage := range manifestStages {
		env, err := o.store.GetEnvironment(o.appName, stage.Name)
		if err != nil {
			return nil, fmt.Errorf("get environment %s in application %s: %w", stage.Name, o.appName, err)
		}

		var stg deploy.PipelineStage
		stg.Init(env, &stage, workloads)
		stages = append(stages, stg)
	}
	return stages, nil
}

func (o packagePipelineOpts) getLocalWorkloads() ([]string, error) {
	var localWklds []string
	if err := o.newSvcListCmd(o.svcBuffer, o.appName).Execute(); err != nil {
		return nil, fmt.Errorf("get local services: %w", err)
	}
	if err := o.newJobListCmd(o.jobBuffer, o.appName).Execute(); err != nil {
		return nil, fmt.Errorf("get local jobs: %w", err)
	}
	svcOutput, jobOutput := &list.ServiceJSONOutput{}, &list.JobJSONOutput{}
	if err := json.Unmarshal(o.svcBuffer.Bytes(), svcOutput); err != nil {
		return nil, fmt.Errorf("unmarshal service list output; %w", err)
	}
	for _, svc := range svcOutput.Services {
		localWklds = append(localWklds, svc.Name)
	}
	if err := json.Unmarshal(o.jobBuffer.Bytes(), jobOutput); err != nil {
		return nil, fmt.Errorf("unmarshal job list output; %w", err)
	}
	for _, job := range jobOutput.Jobs {
		localWklds = append(localWklds, job.Name)
	}
	return localWklds, nil
}

func (o *packagePipelineOpts) getArtifactBuckets() ([]deploy.ArtifactBucket, error) {
	regionalResources, err := o.pipelineDeployer.GetRegionalAppResources(o.app)
	if err != nil {
		return nil, err
	}

	var buckets []deploy.ArtifactBucket
	for _, resource := range regionalResources {
		bucket := deploy.ArtifactBucket{
			BucketName: resource.S3Bucket,
			KeyArn:     resource.KMSKeyARN,
		}
		buckets = append(buckets, bucket)
	}

	return buckets, nil
}
