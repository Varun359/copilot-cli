// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/copilot-cli/internal/pkg/aws/ecr"
	awsecs "github.com/aws/copilot-cli/internal/pkg/aws/ecs"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	clideploy "github.com/aws/copilot-cli/internal/pkg/cli/deploy"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/describe"
	"github.com/aws/copilot-cli/internal/pkg/docker/dockerengine"
	"github.com/aws/copilot-cli/internal/pkg/ecs"
	"github.com/aws/copilot-cli/internal/pkg/exec"
	"github.com/aws/copilot-cli/internal/pkg/manifest"
	"github.com/aws/copilot-cli/internal/pkg/repository"
	"github.com/aws/copilot-cli/internal/pkg/term/color"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/version"
	"github.com/aws/copilot-cli/internal/pkg/workspace"

	//	"github.com/docker/docker/pkg/platform"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type ContainerBuildAndRun interface {
	Build(ctx context.Context, args *dockerengine.BuildArguments, w io.Writer) error
	Run(ctx context.Context, options *dockerengine.Runoptions) error
}

const (
	labelForBuilder       = "com.aws.copilot.image.builder"
	labelForVersion       = "com.aws.copilot.image.version"
	labelForContainerName = "com.aws.copilot.image.container.name"
)

type ecsLocalClient interface {
	TaskDefinition(app, env, svc string) (*awsecs.TaskDefinition, error)
}

type Secret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Engine   string `json:"engine"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	DBName   string `json:"dbname"`
}

type ImageInfo struct {
	ContainerName string
	ImageTag      string
	ImageURI      string
}

type localRunVars struct {
	wkldName string
	appName  string
	envName  string
}

type localRunOpts struct {
	localRunVars

	deployedWkld       []string
	wkldDeployedToEnvs map[string][]string
	//gitShortCommit     string
	//cmd              execRunner
	store            store
	ws               wsWlDirReader
	image            clideploy.ContainerImageIdentifier
	sessProvider     *sessions.Provider
	prompt           prompter
	repository       repositoryService
	ecsLocalClient   ecsLocalClient
	envSess          *session.Session
	docker           ContainerBuildAndRun
	deployStore      deployedEnvironmentLister
	unmarshal        func([]byte) (manifest.DynamicWorkload, error)
	newInterpolator  func(app, env string) interpolator
	envVersionGetter func(string) (versionGetter, error)
}

func newLocalRunOpts(vars localRunVars) (*localRunOpts, error) {
	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("local run"))
	defaultSess, err := sessProvider.Default()
	if err != nil {
		return nil, err
	}

	store := config.NewSSMStore(identity.New(defaultSess), ssm.New(defaultSess), aws.StringValue(defaultSess.Config.Region))
	deployStore, err := deploy.NewStore(sessProvider, store)
	if err != nil {
		return nil, err
	}

	ws, err := workspace.Use(afero.NewOsFs())
	if err != nil {
		return nil, err
	}
	ecsLocalClient := ecs.New(defaultSess)
	repoName := clideploy.RepoName(vars.appName, vars.wkldName)
	gitShortCommit := imageTagFromGit(exec.NewCmd())
	opts := &localRunOpts{
		localRunVars: vars,

		deployedWkld:       []string{},
		wkldDeployedToEnvs: make(map[string][]string),
		unmarshal:          manifest.UnmarshalWorkload,
		newInterpolator:    newManifestInterpolator,
		prompt:             prompt.New(),
		repository:         repository.New(ecr.New(defaultSess), repoName),
		sessProvider:       sessProvider,
		store:              store,
		docker:             dockerengine.New(exec.NewCmd()),
		image: clideploy.ContainerImageIdentifier{
			GitShortCommitTag: gitShortCommit,
		},
		ws:             ws,
		ecsLocalClient: ecsLocalClient,
		deployStore:    deployStore,
	}
	opts.envVersionGetter = func(envName string) (versionGetter, error) {
		envDescriber, err := describe.NewEnvDescriber(describe.NewEnvDescriberConfig{
			App:         opts.appName,
			Env:         envName,
			ConfigStore: opts.store,
		})
		if err != nil {
			return nil, fmt.Errorf("new environment compatibility checker: %v", err)
		}
		return envDescriber, nil
	}
	return opts, nil
}

func (o *localRunOpts) Validate() error {
	if o.appName == "" {
		return errNoAppInWorkspace
	}
	if _, err := o.store.GetApplication(o.appName); err != nil {
		return fmt.Errorf("get application %s: %w", o.appName, err)
	}
	return nil
}

func (o *localRunOpts) Ask() error {
	if err := o.validateOrAskWorkloadName(); err != nil {
		return err
	}
	if err := o.validateOrAskEnvName(); err != nil {
		return err
	}
	return nil
}

func (o *localRunOpts) Execute() error {
	//get TaskDefinition, envVars and secrets
	secrets := make(map[string]string)
	envVars := make(map[string]string)
	awsSession := session.Must(session.NewSessionWithOptions(
		session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))

	taskDef, err := o.ecsLocalClient.TaskDefinition(o.appName, o.envName, o.wkldName)
	if err != nil {
		return fmt.Errorf("get task definition: %w", err)
	}

	for _, containerDef := range taskDef.ContainerDefinitions {
		for _, env := range containerDef.Environment {
			envVars[*env.Name] = *env.Value
		}
	}

	ssmClient := ssm.New(awsSession)

	taskDefSecrets := taskDef.Secrets()
	for _, secret := range taskDefSecrets {
		secretValueFrom := secret.ValueFrom

		decryptedValue, err :=
			ssmClient.GetParameter(&ssm.GetParameterInput{
				Name:           aws.String(secretValueFrom),
				WithDecryption: aws.Bool(true),
			})
		if err != nil {
			return err
		}
		secrets[secret.Name] = *decryptedValue.Parameter.Value
		fmt.Println("The secret Key is ", secret.Name)
		fmt.Println("The secret value is ", *decryptedValue.Parameter.Value)
	}

	secretsManagerClient := secretsmanager.New(awsSession)
	var secretStruct Secret
	var secretsList []Secret
	input := &secretsmanager.ListSecretsInput{}
	err = secretsManagerClient.ListSecretsPages(input, func(page *secretsmanager.ListSecretsOutput, lastPage bool) bool {
		for _, secret := range page.SecretList {
			secretName := *secret.Name
			in := &secretsmanager.GetSecretValueInput{
				SecretId:     aws.String(secretName),
				VersionStage: aws.String("AWSCURRENT"),
			}
			result, _ := secretsManagerClient.GetSecretValue(in)

			secretValue := aws.StringValue(result.SecretString)

			err = json.Unmarshal([]byte(secretValue), &secretStruct)
			secrets[secretStruct.Username] = secretStruct.Password
			secretsList = append(secretsList, secretStruct)
		}
		return !lastPage
	})
	fmt.Println("These are the map of all secrets ", secrets)

	//Get the build info here
	env, err := o.store.GetEnvironment(o.appName, o.envName)
	if err != nil {
		return fmt.Errorf("get environment %s configuration: %w", o.envName, err)
	}
	fmt.Println("The env name is", env.Name)
	envSess, err := o.sessProvider.FromRole(env.ManagerRoleARN, env.Region)
	if err != nil {
		return err
	}
	o.envSess = envSess
	mft, err := workloadManifest(&workloadManifestInput{
		name:         o.wkldName,
		appName:      o.appName,
		envName:      o.envName,
		interpolator: o.newInterpolator(o.appName, o.envName),
		ws:           o.ws,
		unmarshal:    o.unmarshal,
		sess:         envSess,
	})

	workspacePath := o.ws.Path()
	manifestContent := mft.Manifest()

	//dir, err := os.Getwd()
	//fmt.Println("The dir is ", dir)
	// groupName := strings.ToLower(filepath.Base(dir))
	// fmt.Println("The groupName is", groupName)
	//repoName := fmt.Sprintf(deploy.FmtTaskECRRepoName, groupName)
	repoName := fmt.Sprintf("%s/%s", o.appName, o.wkldName)
	uri, _ := ecr.New(o.envSess).RepositoryURI(repoName)
	fmt.Println("The uri is ", uri)
	// fmt.Println("the platform i am runnning in is runtime ", runtime.GOARCH)
	switch t := manifestContent.(type) {
	case *manifest.ScheduledJob:
		scheduleJob := t
		_ = getSideCarImages(scheduleJob.Sidecars)
		buildArgsPerContainer, err := clideploy.BuildArgsPerContainer(o.wkldName, workspacePath, o.image, mft.Manifest())
		if err != nil {
			return err
		}
		fmt.Println("These are the build args per container ", buildArgsPerContainer)
		imageInfoList, err := o.buildImages(buildArgsPerContainer, uri)

		if err != nil {
			return err
		}
		err = o.runImages(imageInfoList, secrets, envVars)
	case *manifest.LoadBalancedWebService:
		LoadBalancedWebService := t
		_ = getSideCarImages(LoadBalancedWebService.Sidecars)
		buildArgsPerContainer, err := clideploy.BuildArgsPerContainer(o.wkldName, workspacePath, o.image, mft.Manifest())
		if err != nil {
			return err
		}
		imageInfoList, err := o.buildImages(buildArgsPerContainer, uri)
		if err != nil {
			return err
		}
		err = o.runImages(imageInfoList, secrets, envVars)
	case *manifest.WorkerService:
		workerService := t
		_ = getSideCarImages(workerService.Sidecars)
		buildArgsPerContainer, err := clideploy.BuildArgsPerContainer(o.wkldName, workspacePath, o.image, mft.Manifest())
		if err != nil {
			return err
		}
		imageInfoList, err := o.buildImages(buildArgsPerContainer, uri)
		if err != nil {
			return err
		}
		err = o.runImages(imageInfoList, secrets, envVars)
	case *manifest.BackendService:
		backendService := t
		_ = getSideCarImages(backendService.Sidecars)
		buildArgsPerContainer, err := clideploy.BuildArgsPerContainer(o.wkldName, workspacePath, o.image, mft.Manifest())
		if err != nil {
			return err
		}
		imageInfoList, err := o.buildImages(buildArgsPerContainer, uri)
		if err != nil {
			return err
		}
		err = o.runImages(imageInfoList, secrets, envVars)
	case *manifest.RequestDrivenWebService:
		buildArgsPerContainer, err := clideploy.BuildArgsPerContainer(o.wkldName, workspacePath, o.image, mft.Manifest())
		if err != nil {
			return err
		}
		imageInfoList, err := o.buildImages(buildArgsPerContainer, uri)
		if err != nil {
			return err
		}
		err = o.runImages(imageInfoList, secrets, envVars)
	}
	return nil
}

func getSideCarImages(sidecars map[string]*manifest.SidecarConfig) map[string]string {
	sideCarImages := make(map[string]string)
	for sideCarName, sidecar := range sidecars {
		if uri, hasLocation := sidecar.ImageURI(); hasLocation {
			sideCarImages[sideCarName] = uri
			fmt.Println("Hey here", uri)
		}
	}
	fmt.Println("\nSidecar Images")
	for sidecarName, build := range sideCarImages {
		fmt.Printf("%s : %s\n", sidecarName, build)
	}
	return sideCarImages
}

func (o *localRunOpts) buildImages(buildArgsPerContainer map[string]*dockerengine.BuildArguments, uri string) ([]ImageInfo, error) {
	var imageInfoList []ImageInfo
	var errGroup errgroup.Group

	maxParallelBuilds := runtime.NumCPU()
	// Create a buffered channel to control the number of parallel builds
	parallelBuilds := make(chan struct{}, maxParallelBuilds)

	// Iterate over the build arguments and perform parallel builds
	for name, buildArgs := range buildArgsPerContainer {
		name := name
		buildArgs := buildArgs

		// Acquire a token from the parallel builds channel
		parallelBuilds <- struct{}{}

		// Execute each build in a separate goroutine
		errGroup.Go(func() error {
			defer func() {
				// Release the token back to the parallel builds channel
				<-parallelBuilds
			}()

			buildArgs.URI = uri
			_, err := buildArgs.GenerateDockerBuildArgs(dockerengine.New(exec.NewCmd()))
			if err != nil {
				return fmt.Errorf("generate docker build args for %q: %w", name, err)
			}
			fmt.Println("these are the tags ", buildArgs.Tags)
			_, err = o.repository.Build(context.Background(), buildArgs, log.DiagnosticWriter)
			if err != nil {
				return fmt.Errorf("build image: %w", err)
			}
			//o.docker.Build(context.Background(), buildArgs, log.DiagnosticWriter)

			imageInfo := ImageInfo{
				ContainerName: name,
				ImageTag:      buildArgs.Tags[0],
				ImageURI:      buildArgs.URI,
			}

			// Append the image info to the list
			imageInfoList = append(imageInfoList, imageInfo)

			return nil
		})
	}

	// Wait for all the builds to complete
	if err := errGroup.Wait(); err != nil {
		return nil, err
	}

	return imageInfoList, nil
}

func (o *localRunOpts) runImages(imageInfoList []ImageInfo, secrets map[string]string, envVars map[string]string) error {
	var errGroup errgroup.Group

	// Iterate over the image info list and perform parallel container runs
	for _, imageInfo := range imageInfoList {
		imageInfo := imageInfo

		// Execute each container run in a separate goroutine
		errGroup.Go(func() error {
			runOptions := &dockerengine.Runoptions{
				ImageURI:      imageInfo.ImageURI,
				Tag:           imageInfo.ImageTag,
				ContainerName: imageInfo.ContainerName,
				Secrets:       secrets,
				EnvVars:       envVars,
			}
			o.docker.Run(context.Background(), runOptions)

			return nil
		})
	}

	// Wait for all the container runs to complete
	if err := errGroup.Wait(); err != nil {
		return err
	}
	return nil
}

func (o *localRunOpts) validateOrAskEnvName() error {
	if o.envName != "" {
		return o.validateEnvName()
	}
	if len(o.wkldDeployedToEnvs[o.wkldName]) == 1 {
		log.Infof("Only one environment found, defaulting to: %s\n", color.HighlightUserInput(o.wkldDeployedToEnvs[o.wkldName][0]))
		o.envName = o.wkldDeployedToEnvs[o.wkldName][0]
		return nil
	}
	selectedEnvName, err := o.prompt.SelectOne("Select an environment in which you want to test", "", o.wkldDeployedToEnvs[o.wkldName], prompt.WithFinalMessage("Environment:"))
	if err != nil {
		return fmt.Errorf("select environment: %w", err)
	}
	o.envName = selectedEnvName
	return nil
}

func (o *localRunOpts) isEnvironmentDeployed(envName string) (bool, error) {
	var checker versionGetter
	checker, err := o.envVersionGetter(envName)
	if err != nil {
		return false, err
	}
	currVersion, err := checker.Version()
	if err != nil {
		return false, fmt.Errorf("get environment %q version: %w", envName, err)
	}
	if currVersion == version.EnvTemplateBootstrap {
		return false, nil
	}
	return true, nil
}

func (o *localRunOpts) validateEnvName() error {
	envs, err := o.deployStore.ListEnvironmentsDeployedTo(o.appName, o.wkldName)
	if err != nil {
		return fmt.Errorf("list deployed environments for application %s: %w", o.appName, err)
	}
	isDeployed, err := o.isEnvironmentDeployed(o.envName)
	if err != nil {
		return err
	}
	if !isDeployed {
		return fmt.Errorf(`cannot use an environment which is not deployed Please run "copilot env deploy, --name %s" to deploy the environment first`, o.envName)
	}
	if !contains(o.envName, envs) {
		return fmt.Errorf("workload %q is not deployed in %q", o.wkldName, o.envName)
	}
	return nil
}

func (o *localRunOpts) validateOrAskWorkloadName() error {
	if o.wkldName != "" {
		return o.validateWkldName()
	}

	localWorkloads, err := o.ws.ListWorkloads()
	if err != nil {
		return fmt.Errorf("list workloads in the workspace %s: %w", o.appName, err)
	}
	for _, wkld := range localWorkloads {
		envs, err := o.deployStore.ListEnvironmentsDeployedTo(o.appName, wkld)
		if err != nil {
			return fmt.Errorf("list deployed environments for application %s: %w", o.appName, err)
		}
		if len(envs) != 0 {
			o.deployedWkld = append(o.deployedWkld, wkld)
			o.wkldDeployedToEnvs[wkld] = envs
		}
	}

	if len(o.deployedWkld) == 0 {
		return fmt.Errorf("no workload is deployed in app %s", o.appName)
	}
	if len(o.deployedWkld) == 1 {
		log.Infof("Only one deployed workload found, defaulting to: %s\n", color.HighlightUserInput(o.deployedWkld[0]))
		o.wkldName = o.deployedWkld[0]
		return nil
	}
	selectedWorkloadName, err := o.prompt.SelectOne("Select a workload that you want to run locally", "", o.deployedWkld, prompt.WithFinalMessage("Workload:"))
	if err != nil {
		return fmt.Errorf("select a Workload: %w", err)
	}
	o.wkldName = selectedWorkloadName
	return nil
}

func (o *localRunOpts) validateWkldName() error {
	names, err := o.ws.ListWorkloads()
	if err != nil {
		return fmt.Errorf("list workloads in the workspace %s : %w", o.wkldName, err)
	}
	if !contains(o.wkldName, names) {
		return fmt.Errorf("workload %q does not exist in the workspace", o.wkldName)
	}
	if _, err := o.store.GetWorkload(o.appName, o.wkldName); err != nil {
		return fmt.Errorf("retrieve %s from application %s: %w", o.wkldName, o.appName, err)
	}
	envs, err := o.deployStore.ListEnvironmentsDeployedTo(o.appName, o.wkldName)
	if err != nil {
		return fmt.Errorf("list deployed environments for application %s: %w", o.appName, err)
	}
	if len(envs) == 0 {
		return fmt.Errorf("workload %q is not deployed in any environment", o.wkldName)
	}
	o.wkldDeployedToEnvs[o.wkldName] = envs
	return nil
}

// BuildLocalRunCmd builds the command for running a workload locally
func BuildLocalRunCmd() *cobra.Command {
	vars := localRunVars{}
	cmd := &cobra.Command{
		Use:    "local run",
		Short:  "Run the workload locally",
		Long:   "Run the workload locally",
		Hidden: true,
		RunE: runCmdE(func(cmd *cobra.Command, args []string) error {
			opts, err := newLocalRunOpts(vars)
			if err != nil {
				return err
			}
			return run(opts)
		}),
	}
	cmd.Flags().StringVarP(&vars.wkldName, nameFlag, nameFlagShort, "", workloadFlagDescription)
	cmd.Flags().StringVarP(&vars.envName, envFlag, envFlagShort, "", envFlagDescription)
	cmd.Flags().StringVarP(&vars.appName, appFlag, appFlagShort, tryReadingAppName(), appFlagDescription)
	return cmd
}
