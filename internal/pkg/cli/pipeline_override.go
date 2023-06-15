package cli

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
	termprogress "github.com/aws/copilot-cli/internal/pkg/term/progress"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/term/selector"
	"github.com/aws/copilot-cli/internal/pkg/workspace"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

type overridePipelineOpts struct {
	*overrideOpts

	// Interfaces to interact with dependencies.
	ws       wsPipelineReader
	fs       afero.Fs
	wsPrompt wsPipelineSelector
	//validateOrAskName func() error
}

func newOverridePipelineOpts(vars overrideVars) (*overridePipelineOpts, error) {
	fs := afero.NewOsFs()
	ws, err := workspace.Use(fs)
	if err != nil {
		return nil, err
	}

	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("pipeline override"))
	defaultSess, err := sessProvider.Default()
	if err != nil {
		return nil, fmt.Errorf("default session: %v", err)
	}

	cfgStore := config.NewSSMStore(identity.New(defaultSess), ssm.New(defaultSess), aws.StringValue(defaultSess.Config.Region))

	prompt := prompt.New()

	cmd := &overridePipelineOpts{
		overrideOpts: &overrideOpts{
			overrideVars: vars,
			fs:           fs,
			cfgStore:     cfgStore,
			prompt:       prompt,
			cfnPrompt:    selector.NewCFNSelector(prompt),
			spinner:      termprogress.NewSpinner(log.DiagnosticWriter),
		},
		ws: ws,
	}
	//cmd.validateOrAskName = cmd.validateOrAskPipelineName
	return cmd, nil
}

// Validate returns an error for any invalid optional flags.
func (o *overridePipelineOpts) Validate() error {
	if err := o.overrideOpts.Validate(); err != nil {
		return err
	}
	return o.validatePipelineName()
}

// Ask prompts for and validates any required flags.
func (o *overridePipelineOpts) Ask() error {
	if o.name == "" {
		return o.askPipelineName()
	}
	return o.overrideOpts.Ask()
}

// Execute writes IaC override files to the local workspace.
func (o *overridePipelineOpts) Execute() error {
	fmt.Println("Hello I am Override command for the pipeline")

	return nil

}

// RecommendActions prints optional follow-up actions.
func (o *overridePipelineOpts) RecommendActions() error {
	return nil
}

func (o *overridePipelineOpts) validatePipelineName() error {
	if o.name == "" {
		return nil
	}
	pipeline_list, err := o.ws.ListPipelines()
	if err != nil {
		return fmt.Errorf("list pipelines in the workspace: %v", err)
	}
	names := []string{}
	for _, pipeline := range pipeline_list {
		names = append(names, pipeline.Name)
	}
	if !contains(o.name, names) {
		return fmt.Errorf("pipeline %q does not exist in the workspace", o.name)
	}
	return nil
}

// func (o *overridePipelineOpts) validateOrAskPipelineName() error {
// 	if o.name == "" {
// 		return o.askPipelineName()
// 	}
// 	return nil
// }

func (o *overridePipelineOpts) askPipelineName() error {
	//fmt.Println("Hey I am inside askPipelineName() function")
	pipeline, err := o.wsPrompt.WsPipeline("Which pipeline's resources would you like to override?", "")
	if err != nil {
		return fmt.Errorf("select pipeline name from workspace: %v", err)
	}
	o.name = pipeline.Name
	return nil
}

func buildPipelineOverrideCmd() *cobra.Command {
	vars := overrideVars{}
	cmd := &cobra.Command{
		Use:   "override",
		Short: "Override the AWS CloudFormation template of a service.",
		Long: `Scaffold Infrastructure as Code patch files. 
Customize the patch files to change resource properties, delete 
or add new resources to the service's AWS CloudFormation template.`,
		Example: `
  Create a new Cloud Development Kit application to override the "frontend" service template.
  /code $ copilot pipeline override -n frontend -e test --toolkit cdk`,

		RunE: runCmdE(func(cmd *cobra.Command, args []string) error {
			opts, err := newOverridePipelineOpts(vars)
			if err != nil {
				return err
			}
			return run(opts)
		}),
	}
	cmd.Flags().StringVarP(&vars.name, nameFlag, nameFlagShort, "", pipelineFlagDescription)
	//cmd.Flags().StringVarP(&vars.envName, envFlag, envFlagShort, "", envFlagDescription)
	cmd.Flags().StringVarP(&vars.appName, appFlag, appFlagShort, tryReadingAppName(), appFlagDescription)
	cmd.Flags().StringVar(&vars.iacTool, iacToolFlag, "", iacToolFlagDescription)
	cmd.Flags().StringVar(&vars.cdkLang, cdkLanguageFlag, typescriptCDKLang, cdkLanguageFlagDescription)
	return cmd
}
