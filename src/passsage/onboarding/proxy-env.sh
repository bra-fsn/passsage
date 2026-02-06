#!/bin/sh

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  if need_cmd sudo; then
    sudo "$@"
    return
  fi
  die "need root privileges for certificate installation (install sudo or run as root)"
}

detect_ca_bundle() {
  for path in \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/ca-bundle.pem \
    /etc/ssl/cert.pem; do
    if [ -f "$path" ]; then
      printf '%s' "$path"
      return
    fi
  done
  printf '%s' ""
}

write_embedded_cert() {
  tmp_cert="$(mktemp -t mitmproxy-ca-XXXXXX.pem)"
  cat > "$tmp_cert" <<'EOF'
__PASSSAGE_MITM_CA_PEM__
EOF
  printf '%s' "$tmp_cert"
}

install_cert_linux() {
  cert="$1"
  if need_cmd update-ca-certificates; then
    dest="/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
    as_root cp "$cert" "$dest"
    as_root update-ca-certificates
    log "installed certificate via update-ca-certificates"
    return
  fi
  if need_cmd update-ca-trust; then
    dest="/etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.crt"
    as_root cp "$cert" "$dest"
    as_root update-ca-trust
    log "installed certificate via update-ca-trust"
    return
  fi
  if need_cmd trust; then
    as_root trust anchor "$cert"
    log "installed certificate via trust anchor"
    return
  fi
  die "could not find a certificate trust tool (update-ca-certificates, update-ca-trust, or trust)"
}

install_cert_macos() {
  cert="$1"
  if ! need_cmd security; then
    die "security command not found (macOS only)"
  fi
  as_root security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain "$cert"
  log "installed certificate in System keychain"
}

install_cert() {
  cert="$1"
  os="$(uname -s)"
  case "$os" in
    Linux)
      install_cert_linux "$cert"
      ;;
    Darwin)
      install_cert_macos "$cert"
      ;;
    *)
      die "unsupported OS: $os"
      ;;
  esac
}

write_env_file() {
  env_dir="${HOME:-$PWD}/.passsage"
  env_file="$env_dir/proxy-env.sh"
  if ! mkdir -p "$env_dir" 2>/dev/null; then
    return
  fi
  if ! {
    printf 'export HTTP_PROXY="%s"\n' "$proxy_url"
    printf 'export HTTPS_PROXY="%s"\n' "$proxy_url"
    printf 'export NO_PROXY="localhost,127.0.0.1,::1,__PASSSAGE_S3_HOST__"\n'
    printf 'export http_proxy="%s"\n' "$proxy_url"
    printf 'export https_proxy="%s"\n' "$proxy_url"
    printf 'export no_proxy="localhost,127.0.0.1,::1,__PASSSAGE_S3_HOST__"\n'
    if [ -n "$ca_bundle" ]; then
      printf 'export SSL_CERT_FILE="%s"\n' "$ca_bundle"
      printf 'export REQUESTS_CA_BUNDLE="%s"\n' "$ca_bundle"
      printf 'export GIT_SSL_CAINFO="%s"\n' "$ca_bundle"
    fi
  } > "$env_file" 2>/dev/null; then
    return
  fi
}

main() {
  log "mitmproxy certificate installer"
  cert="$(write_embedded_cert)"
  install_cert "$cert"

  proxy_url="__PASSSAGE_PUBLIC_PROXY_URL__"
  ca_bundle="$(detect_ca_bundle)"

  export HTTP_PROXY="$proxy_url"
  export HTTPS_PROXY="$proxy_url"
  export NO_PROXY="localhost,127.0.0.1,::1,__PASSSAGE_S3_HOST__"
  export http_proxy="$proxy_url"
  export https_proxy="$proxy_url"
  export no_proxy="localhost,127.0.0.1,::1,__PASSSAGE_S3_HOST__"
  if [ -n "$ca_bundle" ]; then
    export SSL_CERT_FILE="$ca_bundle"
    export REQUESTS_CA_BUNDLE="$ca_bundle"
    export GIT_SSL_CAINFO="$ca_bundle"
  fi

  write_env_file
  log "done"
}

main "$@"
