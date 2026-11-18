import { cookies } from "next/headers";
import { discover, oidc, SESSION_COOKIE } from "@/lib/session";

// End the dashboard session and the Keycloak session behind it.
export async function POST() {
  (await cookies()).delete(SESSION_COOKIE);
  if (!oidc.enabled) return Response.redirect(`${oidc.publicUrl}/`, 303);
  const url = new URL((await discover()).end_session_endpoint);
  url.search = new URLSearchParams({
    client_id: oidc.clientId,
    post_logout_redirect_uri: `${oidc.publicUrl}/`,
  }).toString();
  return Response.redirect(url.toString(), 303);
}
