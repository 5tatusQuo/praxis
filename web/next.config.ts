import type { NextConfig } from "next";

const config: NextConfig = {
  // One self-contained server bundle, so the Docker image stays small.
  output: "standalone",
  poweredByHeader: false,
  // The identity provider is served under the dashboard's own address, at /kc.
  // The browser and this server then agree on one issuer URL, and no second
  // port has to be opened or tunnelled.
  async rewrites() {
    const keycloak = process.env.PRAXIS_KEYCLOAK_INTERNAL_URL ?? "http://keycloak:8080";
    return [{ source: "/kc/:path*", destination: `${keycloak}/kc/:path*` }];
  },
};

export default config;
