import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { discover, LOGIN_COOKIE, oidc, seal } from "@/lib/session";

const b64 = (bytes: Buffer) => bytes.toString("base64url");

// Start sign-in: remember where the user was going, then hand over to Keycloak.
export async function GET(request: Request) {
  if (!oidc.enabled) return Response.redirect(`${oidc.publicUrl}/`, 303);
  const next = new URL(request.url).searchParams.get("next") ?? "/";
  const state = b64(randomBytes(24));
  const nonce = b64(randomBytes(24));
  const verifier = b64(randomBytes(48));
  const challenge = b64(createHash("sha256").update(verifier).digest());
  let endpoints;
  try {
    endpoints = await discover();
  } catch (error) {
    return new Response(`Sign-in is not available yet: ${String(error)}. Try again in a minute.`, { status: 503 });
  }
  (await cookies()).set(LOGIN_COOKIE, await seal({ state, nonce, verifier, next: next.startsWith("/") ? next : "/" }, 0.25), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 900,
  });
  const url = new URL(endpoints.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: oidc.clientId,
    response_type: "code",
    scope: "openid profile email",
    redirect_uri: `${oidc.publicUrl}/login/callback`,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return Response.redirect(url.toString(), 303);
}
