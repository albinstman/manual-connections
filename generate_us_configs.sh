#!/usr/bin/env bash
# Generate WireGuard config files for all PIA US servers.

set -euo pipefail

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  DIM='\033[2m'
  NC='\033[0m'
else
  RED='' GREEN='' BLUE='' BOLD='' DIM='' NC=''
fi

check_tool() {
  if ! command -v "$1" >/dev/null; then
    echo -e "${RED}Error: '$1' not found. Please install $2.${NC}"
    exit 1
  fi
}

check_tool curl curl
check_tool jq jq
check_tool wg wireguard-tools

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/configs}"
CA_CERT="$SCRIPT_DIR/ca.rsa.4096.crt"

if [[ ! -f "$CA_CERT" ]]; then
  echo -e "${RED}Error: CA certificate not found at $CA_CERT${NC}"
  exit 1
fi

# Track failures for summary
declare -a FAILED_SERVERS=()

# --- Authentication ---
if [[ -z "${PIA_TOKEN:-}" ]]; then
  if [[ -z "${PIA_USER:-}" || -z "${PIA_PASS:-}" ]]; then
    echo -e "${RED}Error: Set PIA_USER and PIA_PASS, or provide PIA_TOKEN.${NC}"
    echo ""
    echo "Usage:"
    echo "  PIA_USER=p1234567 PIA_PASS=yourpass ./generate_us_configs.sh [output_dir]"
    echo "  PIA_TOKEN=xxxxx ./generate_us_configs.sh [output_dir]"
    exit 1
  fi
  echo -e "${BLUE}Authenticating as $PIA_USER...${NC}"
  auth_response=$(curl -s --location --request POST \
    "https://www.privateinternetaccess.com/api/client/v2/token" \
    --form "username=$PIA_USER" \
    --form "password=$PIA_PASS")
  PIA_TOKEN=$(echo "$auth_response" | jq -r '.token // empty')
  if [[ -z "$PIA_TOKEN" ]]; then
    echo -e "${RED}Error: Authentication failed.${NC}"
    echo -e "${RED}API response: $auth_response${NC}"
    exit 1
  fi
  echo -e "${GREEN}Token obtained.${NC}"
fi

# --- Fetch server list ---
echo -e "${BLUE}Fetching server list...${NC}"
serverlist_raw=$(curl -s --max-time 15 https://serverlist.piaservers.net/vpninfo/servers/v6)
if [[ -z "$serverlist_raw" ]]; then
  echo -e "${RED}Error: Empty response from server list API. Check your internet connection.${NC}"
  exit 1
fi
# The API returns JSON on line 1, followed by a signature on remaining lines
serverlist_json=$(echo "$serverlist_raw" | head -n 1)
if ! echo "$serverlist_json" | jq empty 2>/dev/null; then
  echo -e "${RED}Error: Failed to parse server list JSON.${NC}"
  echo -e "${RED}First 200 chars of response: ${serverlist_json:0:200}${NC}"
  exit 1
fi

# Filter to US regions only
us_serverlist=$(echo "$serverlist_json" | jq '[.regions[] | select(.id | startswith("us"))]')
region_count=$(echo "$us_serverlist" | jq 'length')
total_wg_servers=$(echo "$us_serverlist" | jq '[.[].servers.wg | length] | add')
echo -e "${GREEN}Found $region_count US regions with $total_wg_servers WireGuard servers.${NC}"
echo ""

# --- Generate configs ---
US_DIR="$OUTPUT_DIR/us"
mkdir -p "$US_DIR"
generated=0
failed=0
region_num=0

for row in $(echo "$us_serverlist" | jq -r '.[] | @base64'); do
  region=$(echo "$row" | base64 -d)
  region_id=$(echo "$region" | jq -r '.id')
  region_name=$(echo "$region" | jq -r '.name')
  wg_count=$(echo "$region" | jq '.servers.wg | length')
  region_num=$((region_num + 1))

  if [[ "$wg_count" -eq 0 ]]; then
    echo -e "${DIM}[$region_num/$region_count] Skipping $region_name ($region_id): no WG servers${NC}"
    continue
  fi

  # Sanitize region name for filename: lowercase, replace spaces/special chars with hyphens
  safe_name=$(echo "$region_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g' | sed 's/^-//;s/-$//')

  for i in $(seq 0 $((wg_count - 1))); do
    wg_ip=$(echo "$region" | jq -r ".servers.wg[$i].ip")
    wg_cn=$(echo "$region" | jq -r ".servers.wg[$i].cn")

    if [[ "$wg_count" -gt 1 ]]; then
      conf_path="$US_DIR/${safe_name}-$((i + 1)).conf"
    else
      conf_path="$US_DIR/${safe_name}.conf"
    fi

    echo -ne "${DIM}[$region_num/$region_count]${NC} $region_name ${DIM}($wg_ip)${NC} ... "

    # Generate ephemeral keys
    privKey=$(wg genkey)
    pubKey=$(echo "$privKey" | wg pubkey)

    # Register key with PIA server
    curl_err=""
    response=$(curl -s -G --max-time 10 \
      --connect-to "$wg_cn::$wg_ip:" \
      --cacert "$CA_CERT" \
      --data-urlencode "pt=${PIA_TOKEN}" \
      --data-urlencode "pubkey=$pubKey" \
      "https://${wg_cn}:1337/addKey" 2>&1) || curl_err="curl failed (exit code $?)"

    # Check for curl-level failure (timeout, connection refused, etc.)
    if [[ -n "$curl_err" ]]; then
      echo -e "${RED}FAILED${NC} - $curl_err"
      [[ -n "$response" ]] && echo -e "  ${DIM}Response: ${response:0:200}${NC}"
      FAILED_SERVERS+=("$region_name [$wg_ip]: $curl_err")
      failed=$((failed + 1))
      continue
    fi

    # Check for empty response
    if [[ -z "$response" ]]; then
      echo -e "${RED}FAILED${NC} - empty response from server"
      FAILED_SERVERS+=("$region_name [$wg_ip]: empty response")
      failed=$((failed + 1))
      continue
    fi

    # Check for valid JSON
    if ! echo "$response" | jq empty 2>/dev/null; then
      echo -e "${RED}FAILED${NC} - invalid JSON response"
      echo -e "  ${DIM}Response: ${response:0:200}${NC}"
      FAILED_SERVERS+=("$region_name [$wg_ip]: invalid JSON")
      failed=$((failed + 1))
      continue
    fi

    # Check API status
    status=$(echo "$response" | jq -r '.status')
    if [[ "$status" != "OK" ]]; then
      message=$(echo "$response" | jq -r '.message // empty')
      echo -e "${RED}FAILED${NC} - status: $status${message:+ ($message)}"
      FAILED_SERVERS+=("$region_name [$wg_ip]: status=$status${message:+ ($message)}")
      failed=$((failed + 1))
      continue
    fi

    peer_ip=$(echo "$response" | jq -r '.peer_ip')
    server_key=$(echo "$response" | jq -r '.server_key')
    server_port=$(echo "$response" | jq -r '.server_port')
    dns_server=$(echo "$response" | jq -r '.dns_servers[0]')

    cat > "$conf_path" <<EOF
[Interface]
Address = $peer_ip
PrivateKey = $privKey
DNS = $dns_server

[Peer]
PersistentKeepalive = 25
PublicKey = $server_key
AllowedIPs = 0.0.0.0/0
Endpoint = ${wg_ip}:${server_port}
EOF

    echo -e "${GREEN}OK${NC} ${DIM}-> $conf_path${NC}"
    generated=$((generated + 1))
  done
done

# --- Summary ---
echo ""
echo -e "${BOLD}========== Summary ==========${NC}"
echo -e "  ${GREEN}Generated: $generated configs${NC}"
echo -e "  ${RED}Failed:    $failed servers${NC}"
echo -e "  Output:   $OUTPUT_DIR"

if [[ ${#FAILED_SERVERS[@]} -gt 0 ]]; then
  echo ""
  echo -e "${RED}Failed servers:${NC}"
  for f in "${FAILED_SERVERS[@]}"; do
    echo -e "  ${RED}- $f${NC}"
  done
fi

echo ""
echo "Use configs with: wg-quick up /path/to/config.conf"
