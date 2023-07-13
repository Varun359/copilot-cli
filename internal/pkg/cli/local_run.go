package cli

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	awsecs "github.com/aws/copilot-cli/internal/pkg/aws/ecs"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/ecs"
	"github.com/aws/copilot-cli/internal/pkg/manifest"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/term/selector"
	"github.com/aws/copilot-cli/internal/pkg/workspace"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	ChooseCredPrompt = "Which credentials would you like to use?"
	credsHelpPrompt  = "The credentials are used to run your workload locally."
)

type ecsLocalClient interface {
	TaskDefinition(app, env, svc string) (*awsecs.TaskDefinition, error)
}

type Manifest struct {
	Image    manifest.Image                     `yaml:"image"`
	Sidecars map[string]*manifest.SidecarConfig `yaml:"sidecars"`
	Build    manifest.BuildArgsOrString         `yaml:"build"`
}

//	type Manifest interface {
//		GetImage() *manifest.Image
//		GetSideCars() map[string]*manifest.SidecarConfig
//		GetFileUploads() []manifest.FileUpload
//		GetPort() int
//	}
type Secret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Engine   string `json:"engine"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	DBName   string `json:"dbname"`
}

type localRunVars struct {
	name    string
	appName string
	envName string
}

type localRunOpts struct {
	localRunVars

	store          store
	ws             wsWlDirReader
	prompt         prompter
	sel            wsSelector
	ecsLocalClient ecsLocalClient

	sess *session.Session

	unmarshal func([]byte) (manifest.DynamicWorkload, error)
	getCreds  func() (credsSelector, error)
}

func newLocalRunOpts(vars localRunVars) (*localRunOpts, error) {
	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("local Run"))
	defaultSess, err := sessProvider.Default()
	if err != nil {
		return nil, err
	}

	store := config.NewSSMStore(identity.New(defaultSess), ssm.New(defaultSess), aws.StringValue(defaultSess.Config.Region))
	ws, err := workspace.Use(afero.NewOsFs())
	if err != nil {
		return nil, err
	}
	// configStore := config.NewSSMStore(identity.New(defaultSess), ssm.New(defaultSess), aws.StringValue(defaultSess.Config.Region))
	// deployStore, err := deploy.NewStore(sessProvider, configStore)
	// if err != nil {
	// 	return nil, fmt.Errorf("connect to deploy store: %w", err)
	// }
	prompter := prompt.New()
	ecsLocalClient := ecs.New(defaultSess)
	opts := &localRunOpts{
		localRunVars: vars,

		sess:           defaultSess,
		store:          store,
		ws:             ws,
		sel:            selector.NewLocalWorkloadSelector(prompter, store, ws),
		unmarshal:      manifest.UnmarshalWorkload,
		prompt:         prompter,
		ecsLocalClient: ecsLocalClient,
		// getCreds: func() (credsSelector, error) {
		// 	cfg, err := profile.NewConfig()
		// 	if err != nil {
		// 		return nil, fmt.Errorf("read named profiles: %w", err)
		// 	}
		// 	return &selector.CredsSelect{
		// 		Session: sessProvider,
		// 		Profile: cfg,
		// 		Prompt:  prompter,
		// 	}, nil
		// },
	}
	return opts, nil
}

func (o *localRunOpts) Validate() error {
	if o.appName == "" {
		return errNoAppInWorkspace
	}
	return nil
}

func (o *localRunOpts) Ask() error {
	if err := o.askEnvName(); err != nil {
		return err
	}
	if err := o.askWorkloadName(); err != nil {
		return err
	}
	return nil
}

func (o *localRunOpts) Execute() error {
	//Stage 1: Get the build info - incomplete
	raw, err := o.ws.ReadWorkloadManifest(o.name)
	if err != nil {
		return fmt.Errorf("read manifest file for %s: %w", o.name, err)
	}
	fmt.Println("This is the manifest", string(raw))

	// Checking the type of manifest here. Don't need???
	am := manifest.Workload{}
	if err := yaml.Unmarshal(raw, &am); err != nil {
		return fmt.Errorf("unmarshal to workload manifest: %w", err)
	}
	typeVal := aws.StringValue(am.Type)
	fmt.Println("TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTttttttttTT", typeVal)

	//Unmarshal the raw manifest
	//var manifest1 manifest.LoadBalancedWebService
	// var manifest2 manifest.BackendService
	// var manifest3 manifest.RequestDrivenWebService
	// var manifest4 manifest.WorkerService
	// var manifest5 manifest.StaticSite
	// var manifest6 manifest.ScheduledJob

	var manifest Manifest

	//manifest = &manifest1
	err = yaml.Unmarshal([]byte(string(raw)), &manifest)
	if err != nil {
		fmt.Printf("Failed to unmarshal manifest :%v\n", err)
	}
	fmt.Println("***This is how unmarshaled manifest looks like", manifest)
	// image := manifest.GetImage()

	// imageString := *image.Build.BuildString

	imageBuild := *&manifest.Image.Build.BuildArgs.Dockerfile
	imageContext := *&manifest.Image.Build.BuildArgs.Context
	imageArgs := *&manifest.Image.Build.BuildArgs.Args
	imageTarget := *&manifest.Image.Build.BuildArgs.Target
	imageCacheFrom := *&manifest.Image.Build.BuildArgs.CacheFrom

	if imageBuild == nil {
		imageBuild = manifest.Image.Build.BuildString
	}
	fmt.Printf("The image is %v\n", *imageBuild)
	if imageContext != nil {
		fmt.Printf("The imageContext is %v\n", *imageContext)
	}
	if imageArgs != nil {
		fmt.Printf("The image args are %v\n", imageArgs)
	}
	if imageTarget != nil {
		fmt.Printf("The imageTarget is %v\n", *imageTarget)
	}
	if imageCacheFrom != nil {
		fmt.Printf("The imageCacheFrom is %v\n", imageCacheFrom)
	}

	//Get the sidecar builds
	sideCarBuilds := make(map[string]string)

	for sideCarName, sidecar := range manifest.Sidecars {
		if uri, hasLocation := sidecar.ImageURI(); hasLocation {
			sideCarBuilds[sideCarName] = uri
			fmt.Println("Hey here", uri)
		}
	}
	fmt.Println("\nSidecar builds")
	for sidecarName, build := range sideCarBuilds {
		fmt.Printf("%s : %s\n", sidecarName, build)
	}

	//Unmarshal the workload
	// workload, err := manifest.UnmarshalWorkload([]byte(raw))

	// if err != nil {
	// 	return fmt.Errorf("Failed to unmarshal workload :%v\n", err)
	// }

	// mani := workload.Manifest()
	// fmt.Println("This is the manifest", mani)

	//Stage 2: Get the task definition - complete
	taskdef, err := o.ecsLocalClient.TaskDefinition(o.appName, o.envName, o.name)
	if err != nil {
		return fmt.Errorf("get task definition: %w", err)
	}

	fmt.Println("*********************Task Definition*********************", taskdef)

	//Stage 3: Get the creds for current user - (seems to be wrong)!!!!!
	configDetails, err := sessions.Creds(o.sess)
	// configDetails, err := o.sess.Config.Credentials.Get()
	fmt.Println("This is the acceskey of the default session is ", configDetails.AccessKeyID)
	fmt.Println("This is the secretkey of the selected session ", configDetails.SecretAccessKey)
	fmt.Println("This is the acceskey of the default session is ", configDetails.SessionToken)
	fmt.Println("This is the provider name ", configDetails.ProviderName)
	fmt.Println("This is the haskeys", configDetails.HasKeys())

	// getCreds, err := o.getCreds()
	// if err != nil {
	// 	return err
	// }

	// sess, err := getCreds.GetCurrentSession(ChooseCredPrompt, credsHelpPrompt)
	// if err != nil {
	// 	return fmt.Errorf("select creds: %w", err)
	// }
	// o.sess = sess

	// stage 4: Decrypt the secrets. - complete as of now
	fmt.Println("The secrets from the task definition are", taskdef.Secrets())

	awsSession := session.Must(session.NewSessionWithOptions(
		session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
	ssmClient := ssm.New(awsSession)

	secrets := taskdef.Secrets()
	for _, secret := range secrets {
		secretName := secret.Name
		secretValueFrom := secret.ValueFrom

		resp, err :=
			ssmClient.GetParameter(&ssm.GetParameterInput{
				Name:           aws.String(secretValueFrom),
				WithDecryption: aws.Bool(true),
			})
		if err != nil {
			return err
		}
		secretValue := *resp.Parameter.Value
		fmt.Println("The secret name and the value is", secretName, secretValue)
	}

	secretsManagerClient := secretsmanager.New(awsSession)
	var secretStruct Secret
	var secretsList []Secret
	input := &secretsmanager.ListSecretsInput{}
	err = secretsManagerClient.ListSecretsPages(input, func(page *secretsmanager.ListSecretsOutput, lastPage bool) bool {
		for _, secret := range page.SecretList {
			secretsString := secret.String()
			fmt.Println("Secret Name:", secretsString)

			secretName := *secret.Name
			input1 := &secretsmanager.GetSecretValueInput{
				SecretId:     aws.String(secretName),
				VersionStage: aws.String("AWSCURRENT"),
			}
			result, _ := secretsManagerClient.GetSecretValue(input1)

			secretValue := aws.StringValue(result.SecretString)

			err = json.Unmarshal([]byte(secretValue), &secretStruct)

			secretsList = append(secretsList, secretStruct)

		}
		return !lastPage
	})

	for _, secret := range secretsList {
		fmt.Printf("secret string is %v", secret.Username)
		fmt.Printf("secret string is %v", secret.Password)
		fmt.Printf("secret string is %v", secret.Host)
		fmt.Printf("secret string is %v", secret.DBName)
		fmt.Printf("secret string is %v", secret.Port)
		fmt.Printf("secret string is %v", secret.Engine)
	}
	return nil
}

func (o *localRunOpts) askEnvName() error {
	if o.envName != "" {
		return nil
	}

	name, err := o.sel.Environment("Select an environment", "", o.appName)
	if err != nil {
		return fmt.Errorf("select environment: %w", err)
	}
	o.envName = name
	return nil
}
func (o *localRunOpts) askWorkloadName() error {
	if o.name != "" {
		return nil
	}

	name, err := o.sel.Workload("Select a workload from your workspace", "")
	if err != nil {
		return fmt.Errorf("select Workload: %w", err)
	}
	o.name = name
	return nil
}

func BuildLocalRunCmd() *cobra.Command {
	vars := localRunVars{}
	cmd := &cobra.Command{
		Use:   "local run",
		Short: "Run the workload locally",
		Long:  "Run the workload locally while replicating the ECS environment",
		RunE: runCmdE(func(cmd *cobra.Command, args []string) error {
			opts, err := newLocalRunOpts(vars)
			if err != nil {
				return err
			}
			return run(opts)
		}),
	}
	cmd.Flags().StringVarP(&vars.name, nameFlag, nameFlagShort, "", workloadFlagDescription)
	cmd.Flags().StringVarP(&vars.envName, envFlag, envFlagShort, "", envFlagDescription)
	cmd.Flags().StringVarP(&vars.appName, appFlag, appFlagShort, tryReadingAppName(), appFlagDescription)

	return cmd
}
