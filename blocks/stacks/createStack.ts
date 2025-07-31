import { AppBlock, events } from "@slflows/sdk/v1";
import { executeSpaceliftQuery, extractCredentials } from "../../client";
import {
  defineSpaceliftInputConfig,
  mapInputConfig,
  mapInputsToGraphQLVariables,
} from "../../utils";

const inputConfig = {
  name: defineSpaceliftInputConfig({
    name: "Name",
    description: "Name of the stack",
    type: "string",
    required: true,
    graphqlFieldKey: "name",
  }),
  namespace: defineSpaceliftInputConfig({
    name: "Namespace",
    description: "Repository namespace (defaults to GitHub account name)",
    type: "string",
    required: false,
    graphqlFieldKey: "namespace",
  }),
  repository: defineSpaceliftInputConfig({
    name: "Repository",
    description: "Repository name",
    type: "string",
    required: true,
    graphqlFieldKey: "repository",
  }),
  branch: defineSpaceliftInputConfig({
    name: "Branch",
    description: "Git branch to track",
    type: "string",
    required: true,
    graphqlFieldKey: "branch",
  }),
  description: defineSpaceliftInputConfig({
    name: "Description",
    description: "Stack description (supports Markdown)",
    type: "string",
    required: false,
    graphqlFieldKey: "description",
  }),
  provider: defineSpaceliftInputConfig({
    name: "VCS provider",
    description: "VCS provider (GITHUB, GITLAB, BITBUCKET_CLOUD, etc.)",
    type: "string",
    required: false,
    graphqlFieldKey: "provider",
  }),
  repositoryURL: defineSpaceliftInputConfig({
    name: "Repository URL",
    description: "Optional URL of the repository",
    type: "string",
    required: false,
    graphqlFieldKey: "repositoryURL",
  }),
  administrative: defineSpaceliftInputConfig({
    name: "Administrative",
    description: "Whether this is an administrative stack",
    type: "boolean",
    required: false,
    graphqlFieldKey: "administrative",
  }),
  autodeploy: defineSpaceliftInputConfig({
    name: "Autodeploy",
    description: "Enable automatic deployments for tracked branches",
    type: "boolean",
    required: false,
    graphqlFieldKey: "autodeploy",
  }),
  autoretry: defineSpaceliftInputConfig({
    name: "Autoretry",
    description: "Automatically retry invalidated Pull Request runs",
    type: "boolean",
    required: false,
    graphqlFieldKey: "autoretry",
  }),
  localPreviewEnabled: defineSpaceliftInputConfig({
    name: "Enable Local Preview",
    description: "Enable local workspace based runs",
    type: "boolean",
    required: false,
    graphqlFieldKey: "localPreviewEnabled",
  }),
  protectFromDeletion: defineSpaceliftInputConfig({
    name: "Protect from deletion",
    description: "Enable deletion protection",
    type: "boolean",
    required: false,
    graphqlFieldKey: "protectFromDeletion",
  }),
  projectRoot: defineSpaceliftInputConfig({
    name: "Project root",
    description:
      "Directory relative to workspace root containing stack entrypoint",
    type: "string",
    required: false,
    graphqlFieldKey: "projectRoot",
  }),
  additionalProjectGlobs: defineSpaceliftInputConfig({
    name: "Additional project globs",
    description: "List of globs that trigger runs when changed",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "additionalProjectGlobs",
  }),
  terraformVersion: defineSpaceliftInputConfig({
    name: "Terraform version",
    description: "Terraform version to use (can be a version range)",
    type: "string",
    required: false,
    graphqlFieldKey: "terraformVersion",
  }),
  runnerImage: defineSpaceliftInputConfig({
    name: "Runner image",
    description: "Custom runner image for processing runs",
    type: "string",
    required: false,
    graphqlFieldKey: "runnerImage",
  }),
  space: defineSpaceliftInputConfig({
    name: "Space ID",
    description: "ID of the space the stack should be in",
    type: "string",
    required: false,
    graphqlFieldKey: "space",
  }),
  vcsIntegrationId: defineSpaceliftInputConfig({
    name: "VCS Integration ID",
    description: "ID of VCS integration (for space-level integrations)",
    type: "string",
    required: false,
    graphqlFieldKey: "vcsIntegrationId",
  }),
  workerPool: defineSpaceliftInputConfig({
    name: "Worker Pool ID",
    description: "ID of the worker pool to use",
    type: "string",
    required: false,
    graphqlFieldKey: "workerPool",
  }),
  githubActionDeploy: defineSpaceliftInputConfig({
    name: "GitHub Action Deploy",
    description: "Enable GitHub Checks 'Deploy' action",
    type: "boolean",
    required: false,
    graphqlFieldKey: "githubActionDeploy",
  }),
  enableWellKnownSecretMasking: defineSpaceliftInputConfig({
    name: "Enable secret masking",
    description: "Enable masking for well-known secrets",
    type: "boolean",
    required: false,
    graphqlFieldKey: "enableWellKnownSecretMasking",
  }),
  enableSensitiveOutputUpload: defineSpaceliftInputConfig({
    name: "Enable sensitive output upload",
    description: "Upload sensitive outputs for stack dependencies",
    type: "boolean",
    required: false,
    graphqlFieldKey: "enableSensitiveOutputUpload",
  }),
  labels: defineSpaceliftInputConfig({
    name: "Labels",
    description: "Stack labels",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "labels",
  }),
  afterApply: defineSpaceliftInputConfig({
    name: "After apply scripts",
    description: "Scripts to run after apply",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "afterApply",
  }),
  beforeApply: defineSpaceliftInputConfig({
    name: "Before apply scripts",
    description: "Scripts to run before apply",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "beforeApply",
  }),
  afterDestroy: defineSpaceliftInputConfig({
    name: "After destroy scripts",
    description: "Scripts to run after destroy",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "afterDestroy",
  }),
  beforeDestroy: defineSpaceliftInputConfig({
    name: "Before destroy scripts",
    description: "Scripts to run before destroy",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "beforeDestroy",
  }),
  afterInit: defineSpaceliftInputConfig({
    name: "After init scripts",
    description: "Scripts to run after init",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "afterInit",
  }),
  beforeInit: defineSpaceliftInputConfig({
    name: "Before init scripts",
    description: "Scripts to run before init",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "beforeInit",
  }),
  afterPlan: defineSpaceliftInputConfig({
    name: "After plan scripts",
    description: "Scripts to run after plan",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "afterPlan",
  }),
  beforePlan: defineSpaceliftInputConfig({
    name: "Before plan scripts",
    description: "Scripts to run before plan",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "beforePlan",
  }),
  afterPerform: defineSpaceliftInputConfig({
    name: "After perform scripts",
    description: "Scripts to run after perform",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "afterPerform",
  }),
  beforePerform: defineSpaceliftInputConfig({
    name: "Before perform scripts",
    description: "Scripts to run before perform",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "beforePerform",
  }),
  afterRun: defineSpaceliftInputConfig({
    name: "After run scripts",
    description: "Scripts to run after any run",
    type: {
      type: "array",
      items: { type: "string" },
    },
    required: false,
    graphqlFieldKey: "afterRun",
  }),
  manageState: defineSpaceliftInputConfig({
    name: "Manage state",
    description: "Let Spacelift manage the Terraform state file",
    type: "boolean",
    required: false,
    graphqlFieldKey: "manageState",
  }),
};

const CREATE_STACK_MUTATION = `
  mutation CreateStack($input: StackInput!, $manageState: Boolean!) {
    stackCreate(input: $input, manageState: $manageState) {
      id
    }
  }
`;

export const createStack: AppBlock = {
  name: "Create stack",
  description: "Create a new Spacelift stack",
  category: "Stacks",
  inputs: {
    default: {
      config: mapInputConfig(inputConfig),
      onEvent: async (input) => {
        const mappedInputs = mapInputsToGraphQLVariables(
          inputConfig,
          input.event.inputConfig,
        );

        const { manageState, ...stackInput } = mappedInputs;

        const createVariables = {
          input: {
            ...stackInput,
            administrative: stackInput.administrative ?? false,
            branch: stackInput.branch || "main",
          },
          manageState: manageState ?? true,
        };

        const credentials = extractCredentials(input.app.config);

        const result = await executeSpaceliftQuery(
          credentials,
          CREATE_STACK_MUTATION,
          createVariables,
        );

        await events.emit({
          id: result.stackCreate.id,
        });
      },
    },
  },
  outputs: {
    default: {
      type: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
        required: ["id"],
      },
    },
  },
};
