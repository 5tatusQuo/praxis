import { NextResponse, type NextRequest } from "next/server";
import { jwtVerify } from "jose";

// Every page needs a signed-in user, except the sign-in pages themselves and
// the identity provider, which is served under /kc.
export async function proxy(request: NextRequest) {
  if (!process.env.PRAXIS_OIDC_ISSUER) return NextResponse.next();
  const publicUrl = process.env.PRAXIS_WEB_URL ?? "http://127.0.0.1:3000";
  const host = request.headers.get("host") ?? "";
  const path = request.nextUrl.pathname + request.nextUrl.search;
  // Sign-in only works at one address, so send every other spelling of it there.
  if (host !== new URL(publicUrl).host) return NextResponse.redirect(`${publicUrl}${path}`);
  const token = request.cookies.get("praxis_session")?.value;
  if (token) {
    try {
      const secret = new TextEncoder().encode(process.env.PRAXIS_SESSION_SECRET ?? "");
      await jwtVerify(token, secret, { algorithms: ["HS256"] });
      return NextResponse.next();
    } catch {
      // fall through to sign-in
    }
  }
  return NextResponse.redirect(`${publicUrl}/login?next=${encodeURIComponent(path)}`);
}

export const config = {
  matcher: ["/((?!kc/|login|logout|_next/|icon.svg|favicon.ico).*)"],
};
