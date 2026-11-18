import { cookies } from "next/headers";
import { discover, ID_TOKEN_COOKIE, oidc, SESSION_COOKIE } from "@/lib/session";

// End the dashboard session and the Keycloak session behind it.
export async function POST() {
  const jar = await cookies();
  const idToken = jar.get(ID_TOKEN_COOKIE)?.value;
  jar.delete(SESSION_COOKIE);
  jar.delete({ name: ID_TOKEN_COOKIE, path: "/logout" });
  if (!oidc.enabled) return Response.redirect(`${oidc.publicUrl}/`, 303);
  const url = new URL((await discover()).end_session_endpoint);
  // With the ID token as a hint, Keycloak ends its session without asking again.
  url.search = new URLSearchParams({
    client_id: oidc.clientId,
    post_logout_redirect_uri: `${oidc.publicUrl}/`,
    ...(idToken ? { id_token_hint: idToken } : {}),
  }).toString();
  return Response.redirect(url.toString(), 303);
}
