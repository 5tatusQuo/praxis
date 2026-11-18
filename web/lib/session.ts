// Dashboard sign-in: OpenID Connect against Keycloak, and a signed session cookie.
//
// Sign-in is on when PRAXIS_OIDC_ISSUER is set (the Compose stack sets it).
// Without it the dashboard is open, which is only for local development.
import { jwtVerify, SignJWT } from "jose";
import { cookies } from "next/headers";

export const SESSION_COOKIE = "praxis_session";
export const LOGIN_COOKIE = "praxis_login";
export const ADMIN_ROLE = "praxis-admin";
const SESSION_HOURS = 8;

export type Session = { name: string; email: string; roles: string[] };

export const oidc = {
  enabled: Boolean(process.env.PRAXIS_OIDC_ISSUER),
  issuer: process.env.PRAXIS_OIDC_ISSUER ?? "",
  clientId: process.env.PRAXIS_OIDC_CLIENT_ID ?? "praxis-web",
  clientSecret: process.env.PRAXIS_OIDC_CLIENT_SECRET ?? "",
  // The one address the dashboard is used at; Keycloak only redirects here.
  publicUrl: process.env.PRAXIS_WEB_URL ?? "http://127.0.0.1:3000",
};

function key(): Uint8Array {
  const secret = process.env.PRAXIS_SESSION_SECRET ?? "";
  if (secret.length < 32) throw new Error("PRAXIS_SESSION_SECRET must be at least 32 characters");
  return new TextEncoder().encode(secret);
}

export async function seal(payload: Record<string, unknown>, hours: number): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${Math.round(hours * 3600)}s`)
    .sign(key());
}

export async function unseal<T>(token: string | undefined): Promise<T | null> {
  if (!token) return null;
  try {
    return (await jwtVerify(token, key(), { algorithms: ["HS256"] })).payload as T;
  } catch {
    return null;
  }
}

export const sealSession = (session: Session) => seal(session, SESSION_HOURS);
export const sessionMaxAge = SESSION_HOURS * 3600;

// The signed-in user, or null. With sign-in off, a local administrator.
export async function currentSession(): Promise<Session | null> {
  if (!oidc.enabled) return { name: "local", email: "", roles: [ADMIN_ROLE] };
  return unseal<Session>((await cookies()).get(SESSION_COOKIE)?.value);
}

// Administrators see every client; anyone else needs the role `client:<id>`.
export function canSee(session: Session | null, clientId: string): boolean {
  if (!session) return false;
  return session.roles.includes(ADMIN_ROLE) || session.roles.includes(`client:${clientId}`);
}

type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint: string;
};

export async function discover(): Promise<Discovery> {
  const response = await fetch(`${oidc.issuer}/.well-known/openid-configuration`, { cache: "no-store" });
  if (!response.ok) throw new Error(`the identity provider answered ${response.status}`);
  return (await response.json()) as Discovery;
}
