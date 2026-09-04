import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

interface PackageMetadata {
  version: string;
}

const frontendDirectory = fileURLToPath(new URL(".", import.meta.url));
const repositoryRoot = path.resolve(frontendDirectory, "..");

const packageMetadata = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8")
) as PackageMetadata;

function readGitCommit(): string {
  try {
    return execFileSync("git", ["rev-parse", "--short=12", "HEAD"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "unknown";
  }
}

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(packageMetadata.version),
    __GIT_COMMIT__: JSON.stringify(readGitCommit())
  },
  server: {
    host: "127.0.0.1",
    port: 5173
  }
});
