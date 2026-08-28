#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command git
require_command curl
require_command unzip
require_command tar
require_command conda

iris_root="${BASELINE_METHOD_ROOT}/iris"
iris_src="${iris_root}/src"
iris_env="${iris_root}/conda-env"
iris_commit="67140e84e6a01da2b44803a6208be2ea7bd4bd51"
cwe_bench_commit="698fb7248ae30cb7f7782d59c841f05ad70ea9cc"
mkdir -p "${iris_root}"

if [[ ! -d "${iris_src}/.git" ]]; then
  git clone --branch v1 https://github.com/iris-sast/iris.git "${iris_src}"
fi
git -C "${iris_src}" fetch --depth 1 origin "${iris_commit}"
git -C "${iris_src}" checkout --detach "${iris_commit}"
git -C "${iris_src}" submodule update --init --recursive

observed_iris="$(git -C "${iris_src}" rev-parse HEAD)"
observed_bench="$(git -C "${iris_src}/data/cwe-bench-java" rev-parse HEAD)"
[[ "${observed_iris}" == "${iris_commit}" ]] || { echo "ERROR: IRIS pin mismatch" >&2; exit 3; }
[[ "${observed_bench}" == "${cwe_bench_commit}" ]] || { echo "ERROR: CWE-Bench pin mismatch" >&2; exit 3; }

if [[ ! -x "${iris_src}/codeql/codeql" ]]; then
  zip_path="${iris_root}/codeql-0.8.3-patched.zip"
  curl -fL "https://github.com/iris-sast/iris/releases/download/codeql-0.8.3-patched/codeql.zip" -o "${zip_path}"
  extract_root="${iris_root}/codeql-extract"
  mkdir -p "${extract_root}"
  unzip -q "${zip_path}" -d "${extract_root}"
  mkdir -p "${iris_src}/codeql"
  cp -a "${extract_root}/codeql/." "${iris_src}/codeql/"
fi

if [[ ! -x "${iris_env}/bin/python" ]]; then
  conda env create --prefix "${iris_env}" --file "${iris_src}/environment.yml"
fi

# The smoke case D002 is pinned by the benchmark to JDK 8u202 and Maven 3.5.0.
# Oracle's archive is login-gated, so the automated cloud harness uses the
# byte-version-equivalent AdoptOpenJDK 8u202-b08 distribution and records that
# vendor deviation explicitly. Detection semantics and IRIS code are unchanged.
java_env="${iris_src}/data/cwe-bench-java/java-env"
mkdir -p "${java_env}"
if [[ ! -x "${java_env}/jdk1.8.0_202/bin/java" ]]; then
  jdk_archive="${iris_root}/OpenJDK8U-jdk_x64_linux_hotspot_8u202b08.tar.gz"
  curl -fL "https://github.com/AdoptOpenJDK/openjdk8-binaries/releases/download/jdk8u202-b08/OpenJDK8U-jdk_x64_linux_hotspot_8u202b08.tar.gz" -o "${jdk_archive}"
  mkdir -p "${java_env}/jdk1.8.0_202"
  tar -xzf "${jdk_archive}" --strip-components=1 -C "${java_env}/jdk1.8.0_202"
fi
if [[ ! -x "${java_env}/apache-maven-3.5.0/bin/mvn" ]]; then
  maven_archive="${iris_root}/apache-maven-3.5.0-bin.tar.gz"
  curl -fL "https://archive.apache.org/dist/maven/maven-3/3.5.0/binaries/apache-maven-3.5.0-bin.tar.gz" -o "${maven_archive}"
  tar -xzf "${maven_archive}" -C "${java_env}"
fi

{
  printf 'iris_commit=%s\n' "${observed_iris}"
  printf 'cwe_bench_commit=%s\n' "${observed_bench}"
  printf 'codeql=%s\n' "$("${iris_src}/codeql/codeql" version --format=terse)"
  printf 'python=%s\n' "$("${iris_env}/bin/python" --version 2>&1)"
  printf 'codeql_zip_sha256=%s\n' "$(sha256sum "${iris_root}/codeql-0.8.3-patched.zip" | cut -d ' ' -f 1)"
  printf 'jdk_smoke=%s\n' "$("${java_env}/jdk1.8.0_202/bin/java" -version 2>&1 | head -n 1)"
  printf 'jdk_vendor_deviation=AdoptOpenJDK_instead_of_login_gated_Oracle_archive\n'
  printf 'jdk_archive_sha256=%s\n' "$(sha256sum "${iris_root}/OpenJDK8U-jdk_x64_linux_hotspot_8u202b08.tar.gz" | cut -d ' ' -f 1)"
  printf 'maven_smoke=%s\n' "$("${java_env}/apache-maven-3.5.0/bin/mvn" --version 2>&1 | head -n 1)"
  printf 'maven_archive_sha256=%s\n' "$(sha256sum "${iris_root}/apache-maven-3.5.0-bin.tar.gz" | cut -d ' ' -f 1)"
} >"${iris_root}/method-lock.txt"

cat "${iris_root}/method-lock.txt"
