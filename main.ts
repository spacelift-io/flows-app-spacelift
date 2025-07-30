import { defineApp, http, kv, blocks, messaging } from "@slflows/sdk/v1";
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { executeSpaceliftQuery, extractCredentials } from "./client";
import { webhook } from "./blocks/stacks/webhook";
import { getStack } from "./blocks/stacks/getStack";
import { lockStack } from "./blocks/stacks/lockStack";
import { unlockStack } from "./blocks/stacks/unlockStack";
import { getContext } from "./blocks/contexts/getContext";
import { getRun } from "./blocks/runs/getRun";
import { getRunLogs } from "./blocks/runs/getRunLogs";
import { startRun } from "./blocks/runs/startRun";
import { attachContextToStack } from "./blocks/contexts/attachContextToStack";
import { detachContextFromStack } from "./blocks/contexts/detachContextFromStack";
import { createPolicy } from "./blocks/policies/createPolicy";
import { deletePolicy } from "./blocks/policies/deletePolicy";
import { updatePolicy } from "./blocks/policies/updatePolicy";
import { getPolicy } from "./blocks/policies/getPolicy";
import { simulatePolicy } from "./blocks/policies/simulatePolicy";
import { getPolicyEvaluations } from "./blocks/policies/getPolicyEvaluations";
import { attachPolicyToStack } from "./blocks/policies/attachPolicyToStack";
import { detachPolicyFromStack } from "./blocks/policies/detachPolicyFromStack";
import { markExternalDependency } from "./blocks/external/markExternalDependency";
import { createContext } from "./blocks/contexts/createContext";
import { updateContext } from "./blocks/contexts/updateContext";
import { contextResource } from "./blocks/contexts/contextResource";
import { deleteContext } from "./blocks/contexts/deleteContext";
import { getEnvironmentVariable } from "./blocks/environmentVariables/getEnvironmentVariable";
import { upsertEnvironmentVariable } from "./blocks/environmentVariables/upsertEnvironmentVariable";
import { deleteEnvironmentVariable } from "./blocks/environmentVariables/deleteEnvironmentVariable";
import { getModule } from "./blocks/modules/getModule";
import { updateModule } from "./blocks/modules/updateModule";
import { deleteModule } from "./blocks/modules/deleteModule";
import { createModule } from "./blocks/modules/createModule";
import { createStack } from "./blocks/stacks/createStack";
import { updateStack } from "./blocks/stacks/updateStack";
import { deleteStack } from "./blocks/stacks/deleteStack";
import { addComment } from "./blocks/runs/addComment";
import { discardRun } from "./blocks/runs/discardRun";
import { retryRun } from "./blocks/runs/retryRun";
import { stopRun } from "./blocks/runs/stopRun";
import { confirmRun } from "./blocks/runs/confirmRun";
import { approveRun } from "./blocks/runs/approveRun";
import { rejectRun } from "./blocks/runs/rejectRun";
import { promoteRun } from "./blocks/runs/promoteRun";
import { triggerRun } from "./blocks/runs/triggerRun";
import { performTask } from "./blocks/tasks/performTask";

export const app = defineApp({
  name: "Spacelift",
  installationInstructions:
    "To connect your Spacelift account:\n1. **Get API Key**: Log in to your Spacelift account and generate an API key\n2. **Configure**: Enter your API Key ID, API Key Secret, and Spacelift endpoint (e.g., 'your-account.app.spacelift.io')\n3. **Confirm**: Click 'Confirm' to complete the installation",
  config: {
    apiKeyId: {
      name: "API Key ID",
      description: "Your Spacelift API key ID",
      type: "string",
      required: true,
    },
    apiKeySecret: {
      name: "API Key Secret",
      description: "Your Spacelift API key secret",
      type: "string",
      required: true,
    },
    endpoint: {
      name: "Spacelift Endpoint",
      description:
        "Your Spacelift endpoint (e.g., 'your-account.app.spacelift.io')",
      type: "string",
      required: true,
    },
    spaceId: {
      name: "Space ID",
      description:
        "The Spacelift space where notification policy and webhook will be created",
      type: "string",
      required: true,
    },
  },
  blocks: {
    // Context operations
    attachContextToStack,
    contextResource,
    createContext,
    deleteContext,
    detachContextFromStack,
    getContext,
    updateContext,

    // Environment variable operations
    upsertEnvironmentVariable,
    deleteEnvironmentVariable,
    getEnvironmentVariable,

    // External operations
    markExternalDependency,

    // Module operations
    createModule,
    deleteModule,
    getModule,
    updateModule,

    // Policy operations
    attachPolicyToStack,
    detachPolicyFromStack,
    createPolicy,
    deletePolicy,
    getPolicy,
    getPolicyEvaluations,
    simulatePolicy,
    updatePolicy,

    // Run operations
    approveRun,
    rejectRun,
    confirmRun,
    startRun,
    stopRun,
    retryRun,
    discardRun,
    addComment,
    promoteRun,
    triggerRun,
    getRun,
    getRunLogs,

    // Stack operations
    getStack,
    webhook,
    createStack,
    deleteStack,
    lockStack,
    unlockStack,
    updateStack,

    // Task operations
    performTask,
  },
  http: {
    onRequest: async (input) => {
      const { request } = input;
      const signature256 = request.headers["X-Signature-256"];

      if (request.method === "POST" && signature256) {
        const webhookPayload = request.body;

        try {
          const webhook = await kv.app.get("webhook");

          if (!webhook?.value?.secret) {
            await http.respond(request.requestId, {
              statusCode: 500,
              body: { error: "Internal server error" },
            });
            return;
          }

          const expectedSignature =
            "sha256=" +
            createHmac("sha256", webhook.value.secret)
              .update(request.rawBody)
              .digest("hex");

          const providedSignature = Buffer.from(signature256);
          const computedSignature = Buffer.from(expectedSignature);

          if (!timingSafeEqual(providedSignature, computedSignature)) {
            await http.respond(request.requestId, {
              statusCode: 401,
              body: { error: "Invalid webhook signature" },
            });
            return;
          }
        } catch (error) {
          await http.respond(request.requestId, {
            statusCode: 500,
            body: { error: "Internal server error" },
          });
          return;
        }

        await http.respond(request.requestId, {
          statusCode: 200,
          body: { message: "Webhook received" },
        });

        const listOutput = await blocks.list({
          typeIds: ["triggerRun", "performTask"],
        });

        if (listOutput.blocks.length > 0) {
          await messaging.sendToBlocks({
            body: {
              payload: webhookPayload,
            },
            blockIds: listOutput.blocks.map((block) => block.id),
          });
        }

        return;
      }

      await http.respond(request.requestId, {
        statusCode: 400,
        body: { error: "Invalid request" },
      });
    },
  },
  async onSync(input) {
    const { spaceId } = input.app.config;

    if (!spaceId) {
      return {
        newStatus: "failed",
        customStatusDescription: "Missing space ID",
      };
    }

    try {
      const credentials = extractCredentials(input.app.config);

      const [existingWebhook, existingPolicyId] = await kv.app.getMany([
        "webhook",
        "notificationPolicyId",
      ]);

      let webhook = existingWebhook?.value;
      let policyId = existingPolicyId?.value;

      if (webhook?.id) {
        try {
          const webhookResult = await executeSpaceliftQuery(
            credentials,
            `
              query GetNamedWebhook($id: ID!) {
                namedWebhooksIntegration(id: $id) {
                  id
                  enabled
                  endpoint
                  space {
                    id
                  }
                }
              }
            `,
            { id: webhook.id },
          );

          if (!webhookResult.namedWebhooksIntegration) {
            webhook = null;
            await kv.app.delete(["webhook"]);
          } else {
            const readableWebhookName = `Flows Webhook (${input.app.installationUrl})`;

            await executeSpaceliftQuery(
              credentials,
              `
                mutation UpdateNamedWebhook($id: ID!, $input: NamedWebhooksIntegrationInput!) {
                  namedWebhooksIntegrationUpdate(id: $id, input: $input) {
                    id
                    name
                  }
                }
              `,
              {
                id: webhook.id,
                input: {
                  space: spaceId,
                  name: readableWebhookName,
                  endpoint: input.app.http.url,
                  enabled: true,
                  labels: ["flows"],
                  secret: webhook.secret,
                },
              },
            );
          }
        } catch {
          webhook = null;
          await kv.app.delete(["webhook"]);
        }
      }

      if (!webhook) {
        const uniqueWebhookName = `flows-${crypto.randomUUID()}`;
        const readableWebhookName = `Flows Webhook (${input.app.installationUrl})`;

        const webhookSecret = randomBytes(32).toString("hex");

        try {
          const webhookResult = await executeSpaceliftQuery(
            credentials,
            `
              mutation CreateNamedWebhook($input: NamedWebhooksIntegrationInput!) {
                namedWebhooksIntegrationCreate(input: $input) {
                  id
                  name
                  endpoint
                  enabled
                }
              }
            `,
            {
              input: {
                space: spaceId,
                name: uniqueWebhookName,
                endpoint: input.app.http.url,
                enabled: true,
                labels: ["flows"],
                secret: webhookSecret,
              },
            },
          );

          const webhookId = webhookResult.namedWebhooksIntegrationCreate.id;

          await executeSpaceliftQuery(
            credentials,
            `
              mutation UpdateNamedWebhook($id: ID!, $input: NamedWebhooksIntegrationInput!) {
                namedWebhooksIntegrationUpdate(id: $id, input: $input) {
                  id
                  name
                }
              }
            `,
            {
              id: webhookId,
              input: {
                space: spaceId,
                name: readableWebhookName,
                endpoint: input.app.http.url,
                enabled: true,
                labels: ["flows"],
                secret: webhookSecret,
              },
            },
          );

          webhook = { id: webhookId, secret: webhookSecret };
          await kv.app.set({ key: "webhook", value: webhook });
        } catch {
          return {
            newStatus: "failed",
            customStatusDescription: `Failed to create webhook`,
          };
        }
      }

      if (!policyId) {
        try {
          const policyResult = await executeSpaceliftQuery(
            credentials,
            `
              mutation CreatePolicy($input: PolicyCreateInput!) {
                policyCreatev2(input: $input) {
                  id
                  name
                  body
                  type
                }
              }
            `,
            {
              input: {
                name: `Flows Notification Policy (${input.app.installationUrl})`,
                body: `package spacelift

# Default notification policy that routes all notifications to Flows webhook
webhook[{"endpoint_id": endpoint.id}] {
  endpoint := input.webhook_endpoints[_]
  endpoint.id == "${webhook.id}"
}`,
                type: "NOTIFICATION",
                space: spaceId,
                labels: ["flows"],
                description:
                  "Notification policy for routing Spacelift events to Flows webhook",
              },
            },
          );

          await kv.app.set({
            key: "notificationPolicyId",
            value: policyResult.policyCreatev2.id,
          });
        } catch {
          return {
            newStatus: "failed",
            customStatusDescription: `Failed to create notification policy`,
          };
        }
      }

      return { newStatus: "ready" };
    } catch (error) {
      return {
        newStatus: "failed",
        customStatusDescription: `Setup failed`,
      };
    }
  },
});
