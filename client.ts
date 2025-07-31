import { kv } from "@slflows/sdk/v1";

interface SpaceliftCredentials {
  apiKeyId: string;
  apiKeySecret: string;
  endpoint: string;
}

interface SpaceliftApiResponse<T = any> {
  data?: T;
  errors?: Array<{ message: string; extensions?: any }>;
}

interface CachedJWTToken {
  jwt: string;
}

function getCacheKey(credentials: SpaceliftCredentials): string {
  return `spacelift_jwt_${credentials.endpoint}_${credentials.apiKeyId}`;
}

export function extractCredentials(
  appConfig: Record<string, any>,
): SpaceliftCredentials {
  if (!appConfig.apiKeyId || !appConfig.apiKeySecret || !appConfig.endpoint) {
    throw new Error("Missing required Spacelift credentials in app config");
  }

  return {
    apiKeyId: appConfig.apiKeyId,
    apiKeySecret: appConfig.apiKeySecret,
    endpoint: appConfig.endpoint,
  };
}

async function fetchNewJWT(
  credentials: SpaceliftCredentials,
): Promise<{ jwt: string; validUntil: number }> {
  const response = await fetch(`https://${credentials.endpoint}/graphql`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: `
        mutation GetSpaceliftToken($id: ID!, $secret: String!) {
          apiKeyUser(id: $id, secret: $secret) {
            jwt
            validUntil
          }
        }
      `,
      variables: {
        id: credentials.apiKeyId,
        secret: credentials.apiKeySecret,
      },
    }),
  });

  const result: SpaceliftApiResponse<{
    apiKeyUser: { jwt: string; validUntil: number };
  }> = await response.json();

  if (result.errors) {
    throw new Error(
      `Authentication failed: ${result.errors.map((e) => e.message).join(", ")}`,
    );
  }

  if (!result.data?.apiKeyUser?.jwt || !result.data?.apiKeyUser?.validUntil) {
    throw new Error("Failed to obtain JWT token or expiration time");
  }

  return {
    jwt: result.data.apiKeyUser.jwt,
    validUntil: result.data.apiKeyUser.validUntil,
  };
}

export async function getSpaceliftJWT(
  credentials: SpaceliftCredentials,
): Promise<string> {
  const cacheKey = getCacheKey(credentials);

  const cachedToken = await kv.app.get(cacheKey);

  if (cachedToken.value) {
    const cached = cachedToken.value as CachedJWTToken;
    return cached.jwt;
  }

  const { jwt, validUntil } = await fetchNewJWT(credentials);

  // Cache the new token with TTL (5 minute safety buffer)
  const now = Math.floor(Date.now() / 1000);
  const ttlSeconds = Math.max(validUntil - now - 300, 60); // At least 1 minute TTL

  await kv.app.set({
    key: cacheKey,
    value: {
      jwt,
    } as CachedJWTToken,
    ttl: ttlSeconds,
  });

  return jwt;
}

export async function executeSpaceliftQuery<T = any>(
  credentials: SpaceliftCredentials,
  query: string,
  variables?: Record<string, any>,
): Promise<T> {
  const jwt = await getSpaceliftJWT(credentials);

  const response = await fetch(`https://${credentials.endpoint}/graphql`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify({
      query,
      variables,
    }),
  });

  const result: SpaceliftApiResponse<T> = await response.json();

  if (result.errors) {
    throw new Error(
      `GraphQL error: ${result.errors.map((e) => e.message).join(", ")}`,
    );
  }

  if (!result.data) {
    throw new Error("No data returned from Spacelift API");
  }

  return result.data;
}
