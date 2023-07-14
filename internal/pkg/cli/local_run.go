// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	awsecs "github.com/aws/copilot-cli/internal/pkg/aws/ecs"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/describe"
	"github.com/aws/copilot-cli/internal/pkg/ecs"
	"github.com/aws/copilot-cli/internal/pkg/manifest"
	"github.com/aws/copilot-cli/internal/pkg/term/color"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/version"
	"github.com/aws/copilot-cli/internal/pkg/workspace"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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

type localRunVars struct {
	wkldName string
	appName  string
	envName  string
}

type localRunOpts struct {
	localRunVars

	deployedWkld       []string
	wkldDeployedToEnvs map[string][]string
	store              store
	ws                 wsWlDirReader
	prompt             prompter
	ecsLocalClient     ecsLocalClient
	deployStore        deployedEnvironmentLister
	envVersionGetter   func(string) (versionGetter, error)
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
	opts := &localRunOpts{
		localRunVars: vars,

		deployedWkld:       []string{},
		wkldDeployedToEnvs: make(map[string][]string),
		prompt:             prompt.New(),
		store:              store,
		ws:                 ws,
		ecsLocalClient:     ecsLocalClient,
		deployStore:        deployStore,
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
	taskDef, err := o.ecsLocalClient.TaskDefinition(o.appName, o.envName, o.wkldName)
	if err != nil {
		return fmt.Errorf("get task definition: %w", err)
	}

	awsSession := session.Must(session.NewSessionWithOptions(
		session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
	ssmClient := ssm.New(awsSession)

	secrets := taskDef.Secrets()
	for _, secret := range secrets {
		secretValueFrom := secret.ValueFrom

		_, err :=
			ssmClient.GetParameter(&ssm.GetParameterInput{
				Name:           aws.String(secretValueFrom),
				WithDecryption: aws.Bool(true),
			})
		if err != nil {
			return err
		}
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

			secretsList = append(secretsList, secretStruct)
		}
		return !lastPage
	})

	//Get the build info here
	raw, err := o.ws.ReadWorkloadManifest(o.wkldName)
	if err != nil {
		return fmt.Errorf("read manifest file for %s: %w", o.wkldName, err)
	}

	am := manifest.Workload{}
	if err := yaml.Unmarshal(raw, &am); err != nil {
		return fmt.Errorf("unmarshal to workload manifest: %w", err)
	}
	typeVal := aws.StringValue(am.Type)

	dirPath, _ := filepath.Abs(".")

	//should write a switch to get the build Args based on the type of the manifest
	var manifest *manifest.WorkerService
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("unmarshal manifest for %s: %w", typeVal, err)
	}
	imageArgs, err := manifest.BuildArgs(dirPath)
	fmt.Println("image args are", imageArgs)

	// for _, image := range imageArgs {
	// 	imageArgsDockerFile := *image.Dockerfile
	// 	imageArgsArgs := image.Args
	// 	imageArgsCache := image.CacheFrom
	// 	imageArgsTarget := image.Target
	// 	imageArgsContext := *image.Context
	// }

	//SideCar Images has the list of sidecar images
	sideCarImages := make(map[string]string)

	for sideCarName, sidecar := range manifest.Sidecars {
		if uri, hasLocation := sidecar.ImageURI(); hasLocation {
			sideCarImages[sideCarName] = uri
			fmt.Println("Hey here", uri)
		}
	}
	fmt.Println("\nSidecar Images")
	for sidecarName, build := range sideCarImages {
		fmt.Printf("%s : %s\n", sidecarName, build)
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
		return fmt.Errorf("list workloads in the workspace %s : %w", o.appName, err)
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
	selectedWorloadName, err := o.prompt.SelectOne("Select a workload that you want to run locally", "", o.deployedWkld, prompt.WithFinalMessage("workload name"))
	if err != nil {
		return fmt.Errorf("select Workload: %w", err)
	}
	o.wkldName = selectedWorloadName
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
