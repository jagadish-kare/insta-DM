import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "crypto";
import { getEncryptionKeyHex, getMetaGraphApiVersion, requireEnv } from "@/lib/env";

// Using Facebook Login OAuth to get Instagram Business access
const FACEBOOK_OAUTH_URL = "https://www.facebook.com/v21.0/dialog/oauth";
const FACEBOOK_TOKEN_URL = "https://graph.facebook.com/v21.0/oauth/access_token";
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

interface OAuthStatePayload {
  workspaceId: string;
  ts: number;
}

function base64UrlEncode(value: string): string {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signState(payload: string): string {
  return createHmac("sha256", requireEnv("NEXTAUTH_SECRET"))
    .update(payload)
    .digest("base64url");
}

export function createOAuthState(workspaceId: string): string {
  const payload = base64UrlEncode(
    JSON.stringify({ workspaceId, ts: Date.now() } satisfies OAuthStatePayload)
  );
  return `${payload}.${signState(payload)}`;
}

export function verifyOAuthState(state: string | null): OAuthStatePayload | null {
  if (!state) return null;

  const [payload, signature] = state.split(".");
  if (!payload || !signature) return null;

  const expected = signState(payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecode(payload)) as OAuthStatePayload;
    if (!parsed.workspaceId || Date.now() - parsed.ts > STATE_MAX_AGE_MS) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

export function getAuthorizationUrl(redirectUri: string, state: string): string {
  // Facebook Login scopes for Instagram Business access
  // These scopes allow managing Instagram Business accounts connected to Facebook Pages
  const scopes = [
    "instagram_basic",
    "instagram_manage_messages", 
    "instagram_manage_comments",
    "instagram_content_publish",
    "pages_show_list",
    "pages_read_engagement",
    "business_management",
  ].join(",");

  const params = new URLSearchParams({
    client_id: requireEnv("INSTAGRAM_APP_ID"),
    redirect_uri: redirectUri,
    scope: scopes,
    response_type: "code",
    state,
  });

  return `${FACEBOOK_OAUTH_URL}?${params.toString()}`;
}

export async function exchangeCodeForToken(
  code: string,
  redirectUri: string
): Promise<{ accessToken: string; userId: string }> {
  // Exchange code for Facebook access token
  const tokenUrl = new URL(FACEBOOK_TOKEN_URL);
  tokenUrl.searchParams.set("client_id", requireEnv("INSTAGRAM_APP_ID"));
  tokenUrl.searchParams.set("client_secret", requireEnv("INSTAGRAM_APP_SECRET"));
  tokenUrl.searchParams.set("redirect_uri", redirectUri);
  tokenUrl.searchParams.set("code", code);

  const response = await fetch(tokenUrl.toString(), {
    method: "GET",
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(
      `Token exchange failed: ${error.error?.message || JSON.stringify(error)}`
    );
  }

  const data = await response.json();
  const fbAccessToken = data.access_token;

  // Get the Facebook user ID
  const meResponse = await fetch(
    `https://graph.facebook.com/v21.0/me?access_token=${fbAccessToken}`
  );
  const meData = await meResponse.json();
  
  // Get Facebook Pages connected to this user
  const pagesResponse = await fetch(
    `https://graph.facebook.com/v21.0/me/accounts?access_token=${fbAccessToken}`
  );
  const pagesData = await pagesResponse.json();
  
  if (!pagesData.data || pagesData.data.length === 0) {
    throw new Error("No Facebook Pages found. Please connect your Instagram Business account to a Facebook Page first.");
  }

  // Get the first page's access token and find connected Instagram account
  const page = pagesData.data[0];
  const pageAccessToken = page.access_token;
  
  // Get Instagram Business Account connected to this Page
  const igAccountResponse = await fetch(
    `https://graph.facebook.com/v21.0/${page.id}?fields=instagram_business_account&access_token=${pageAccessToken}`
  );
  const igAccountData = await igAccountResponse.json();
  
  if (!igAccountData.instagram_business_account) {
    throw new Error("No Instagram Business account connected to your Facebook Page. Please connect your Instagram Business/Creator account to your Facebook Page first.");
  }

  const instagramAccountId = igAccountData.instagram_business_account.id;

  return {
    accessToken: pageAccessToken, // Use Page access token for Instagram API calls
    userId: instagramAccountId,
  };
}

function getEncryptionKey(): Buffer {
  return Buffer.from(getEncryptionKeyHex(), "hex");
}

export function encryptToken(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, authTag, encrypted]);

  return combined.toString("base64");
}

export function decryptToken(encryptedBase64: string): string {
  const key = getEncryptionKey();
  const combined = Buffer.from(encryptedBase64, "base64");

  const iv = combined.subarray(0, IV_LENGTH);
  const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
    "utf8"
  );
}
