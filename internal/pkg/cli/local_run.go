package cli

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	awsecs "github.com/aws/copilot-cli/internal/pkg/aws/ecs"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/profile"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/ecs"
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
	Image struct {
		Build string `yaml:"build"`
	} `yaml:"image"`
}

type localRunVars struct {
	name    string
	appName string
	envName string
}

type localRunOpts struct {
	localRunVars
	//ecsServiceDescriber

	store          store
	ws             wsWlDirReader
	prompt         prompter
	sel            wsSelector
	ecsLocalClient ecsLocalClient

	sess *session.Session

	getCreds func() (credsSelector, error)
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
	prompter := prompt.New()
	ecsLocalClient := ecs.New(defaultSess)
	opts := &localRunOpts{
		localRunVars: vars,

		store:          store,
		ws:             ws,
		sel:            selector.NewLocalWorkloadSelector(prompter, store, ws),
		prompt:         prompter,
		ecsLocalClient: ecsLocalClient,
		getCreds: func() (credsSelector, error) {
			cfg, err := profile.NewConfig()
			if err != nil {
				return nil, fmt.Errorf("read named profiles: %w", err)
			}
			return &selector.CredsSelect{
				Session: sessProvider,
				Profile: cfg,
				Prompt:  prompter,
			}, nil
		},
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
	fmt.Printf("The app name that you want to run locally is %v\n", o.appName)
	fmt.Printf("The env name that you want to run locally is %v\n", o.envName)
	fmt.Printf("The svc name that you want to run locally is %v\n", o.name)

	//Stage 1: Get the build info
	raw, err := o.ws.ReadWorkloadManifest(o.name)
	if err != nil {
		return fmt.Errorf("read manifest file for %s: %w", o.name, err)
	}
	fmt.Println("This is the manifest", string(raw))

	//Unmarshal the raw manifest
	var manifest Manifest

	err = yaml.Unmarshal([]byte(string(raw)), &manifest)
	if err != nil {
		fmt.Printf("Failed to unmarshal manifest :%v\n", err)
	}
	imageBuild := manifest.Image.Build
	fmt.Printf("The image is %v", imageBuild)

	//Stage 2: Get the task definition
	taskdef, err := o.ecsLocalClient.TaskDefinition(o.appName, o.envName, o.name)
	if err != nil {
		return fmt.Errorf("get task definition: %w", err)
	}

	fmt.Println("*********************Task Definition*********************", taskdef)

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
	//Stage 3: Get the creds for current user
	getCreds, err := o.getCreds()
	if err != nil {
		return err
	}

	sess, err := getCreds.GetCurrentSession(ChooseCredPrompt, credsHelpPrompt)
	if err != nil {
		return fmt.Errorf("select creds: %w", err)
	}
	o.sess = sess

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
