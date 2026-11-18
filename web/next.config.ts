import type { NextConfig } from "next";

const config: NextConfig = {
  // One self-contained server bundle, so the Docker image stays small.
  output: "standalone",
  poweredByHeader: false,
};

export default config;
