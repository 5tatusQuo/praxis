import { createRemoteJWKSet, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { discover, LOGIN_COOKIE, oidc, sealSession, SESSION_COOKIE, sessionMaxAge, unseal } from "@/lib/session";

type Pending = { state: string; nonce: string; verifier: string; next: string };

// Keycloak sends the browser back here with a code. Exchange it, check the ID
// token, and start the session.
export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const jar = await cookies();
  const pending = await unseal<Pending>(jar.get(LOGIN_COOKIE)?.value);
  jar.delete(LOGIN_COOKIE);
  const fail = (reason: string) => new Response(`Sign-in failed: ${reason}. Go back to ${oidc.publicUrl}/login to try again.`, { status: 400 });
  if (!pending || params.get("state") !== pending.state) return fail("this sign-in attempt is unknown or has expired");
  if (params.get("error")) return fail(params.get("error_description") ?? params.get("error") ?? "refused");
  const endpoints = await discover();
  const exchange = await fetch(endpoints.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.get("code") ?? "",
      redirect_uri: `${oidc.publicUrl}/login/callback`,
      client_id: oidc.clientId,
      client_secret: oidc.clientSecret,
      code_verifier: pending.verifier,
    }),
    cache: "no-store",
  });
  if (!exchange.ok) return fail(`the identity provider refused the code (${exchange.status})`);
  const tokens = (await exchange.json()) as { id_token: string };
  let claims;
  try {
    claims = (
      await jwtVerify(tokens.id_token, createRemoteJWKSet(new URL(endpoints.jwks_uri)), {
        issuer: oidc.issuer,
        audience: oidc.clientId,
      })
    ).payload;
  } catch (error) {
    return fail(`the ID token did not verify (${String(error)})`);
  }
  if (claims.nonce !== pending.nonce) return fail("the ID token does not belong to this attempt");
  const session = {
    name: String(claims.name ?? claims.preferred_username ?? "user"),
    email: String(claims.email ?? ""),
    roles: Array.isArray(claims.roles) ? claims.roles.map(String) : [],
  };
  jar.set(SESSION_COOKIE, await sealSession(session), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: sessionMaxAge,
  });
  return Response.redirect(`${oidc.publicUrl}${pending.next}`, 303);
}
