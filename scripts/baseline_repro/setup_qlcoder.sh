#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command git
require_command curl
require_command tar
require_command docker

ql_root="${BASELINE_METHOD_ROOT}/qlcoder"
ql_src="${ql_root}/src"
lsp_src="${ql_root}/codeql-lsp-mcp"
codeql_home="${ql_root}/codeql-2.22.2"
ql_commit="6095f90f3b4906f36e2e2fe7d1d0bc987750ca2b"
lsp_commit="a33ea82bba156dc8352a0ecd85baff34cbb950ed"
mkdir -p "${ql_root}"

if [[ ! -d "${ql_src}/.git" ]]; then
  git clone https://github.com/neuralprogram/qlcoder.git "${ql_src}"
fi
git -C "${ql_src}" fetch --depth 1 origin "${ql_commit}"
git -C "${ql_src}" checkout --detach "${ql_commit}"

if [[ ! -d "${lsp_src}/.git" ]]; then
  git clone https://github.com/neuralprogram/codeql-lsp-mcp.git "${lsp_src}"
fi
git -C "${lsp_src}" fetch --depth 1 origin "${lsp_commit}"
git -C "${lsp_src}" checkout --detach "${lsp_commit}"

if [[ ! -x "${codeql_home}/codeql" ]]; then
  bundle_path="${ql_root}/codeql-bundle-linux64-2.22.2.tar.gz"
  curl -fL "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.22.2/codeql-bundle-linux64.tar.gz" -o "${bundle_path}"
  extract_root="${ql_root}/codeql-extract"
  mkdir -p "${extract_root}"
  tar -xzf "${bundle_path}" -C "${extract_root}"
  mv "${extract_root}/codeql" "${codeql_home}"
fi

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e npm_config_cache=/tmp/npm-cache \
  -v "${lsp_src}:/work" \
  -w /work \
  node:24-bookworm sh -lc 'npm install && npm run build'

cp "${ql_src}/Dockerfile" "${ql_src}/Dockerfile.paper"
sed -i 's|npm install -g @anthropic-ai/claude-code$|npm install -g @anthropic-ai/claude-code@1.0.120|' "${ql_src}/Dockerfile.paper"
cat >"${ql_src}/docker-compose.baseline.yml" <<'EOF'
services:
  app:
    build:
      dockerfile: Dockerfile.paper
    volumes:
      - ${BASELINE_OUTPUT_ROOT}:/baseline-output
EOF

security_pack="$(find "${codeql_home}/qlpacks/codeql/java-queries" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
library_pack="$(find "${codeql_home}/qlpacks/codeql/java-all" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
security_version="$(basename "${security_pack}")"
library_version="$(basename "${library_pack}")"
{
  printf 'export CODEQL_HOME=%q\n' "${codeql_home}"
  printf 'export CODEQL_LSP_MCP_HOME=%q\n' "${lsp_src}"
  printf 'export BASELINE_OUTPUT_ROOT=%q\n' "${BASELINE_ARTIFACT_ROOT}"
  printf 'export SECURITY_QLPACK_PATH=%q\n' "/opt/codeql/qlpacks/codeql/java-queries/${security_version}/Security/CWE"
  printf 'export LIBRARY_QLPACK_PATH=%q\n' "/opt/codeql/qlpacks/codeql/java-all/${library_version}/semmle/code/java"
} >"${ql_root}/method.env"
source "${ql_root}/method.env"

(
  cd "${ql_src}"
  docker compose -f docker-compose.yml -f docker-compose.baseline.yml build app
  docker compose -f docker-compose.yml -f docker-compose.baseline.yml pull chroma
  docker compose -f docker-compose.yml -f docker-compose.baseline.yml up -d chroma
  docker compose -f docker-compose.yml -f docker-compose.baseline.yml run --rm app python3 scripts/codeql_docs_fetcher.py
  docker compose -f docker-compose.yml -f docker-compose.baseline.yml run --rm app python3 scripts/cwe_fetcher.py
)

{
  printf 'qlcoder_commit=%s\n' "$(git -C "${ql_src}" rev-parse HEAD)"
  printf 'codeql_lsp_mcp_commit=%s\n' "$(git -C "${lsp_src}" rev-parse HEAD)"
  printf 'codeql=%s\n' "$("${codeql_home}/codeql" version --format=terse)"
  printf 'codeql_bundle_sha256=%s\n' "$(sha256sum "${ql_root}/codeql-bundle-linux64-2.22.2.tar.gz" | cut -d ' ' -f 1)"
  printf 'claude_code=1.0.120\n'
  printf 'model=claude-sonnet-4-20250514\n'
  printf 'agent=claude\n'
  printf 'max_iterations=5\n'
  printf 'docker_compose=%s\n' "$(docker compose version --short)"
  printf 'chroma_image=%s\n' "$(docker image inspect chromadb/chroma:latest --format '{{.Id}}' 2>/dev/null || printf UNAVAILABLE)"
} >"${ql_root}/method-lock.txt"

cat "${ql_root}/method-lock.txt"
