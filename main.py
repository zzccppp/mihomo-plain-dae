import ipaddress
import logging
from time import time
from urllib.parse import quote, urlparse

import requests
import yaml
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------------------------------------------------------------------------
# SSRF protection — block private / reserved IPs
# ---------------------------------------------------------------------------
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::/128"),
]

BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "metadata.google.internal"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB


def _is_private_host(host: str) -> bool:
    """Check whether a hostname resolves to a private/internal IP."""
    host = host.lower().strip().rstrip(".")
    if host in BLOCKED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # hostname, try to resolve
        import socket
        try:
            info = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
            for _, _, _, _, sockaddr in info:
                ip = sockaddr[0]
                addr = ipaddress.ip_address(ip)
                if any(addr in net for net in PRIVATE_NETWORKS):
                    return True
            return False
        except socket.gaierror:
            return True  # cannot resolve — block by default
    else:
        return any(addr in net for net in PRIVATE_NETWORKS)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
_rate_window = 60      # seconds
_rate_max = 30         # requests per window
_rate_buckets: dict[str, list[float]] = {}


def _rate_limit(ip: str) -> bool:
    """Return True if this IP should be rate-limited."""
    now = time()
    bucket = _rate_buckets.get(ip)
    if bucket is None:
        _rate_buckets[ip] = [now]
        return False
    # Prune old timestamps
    bucket[:] = [t for t in bucket if now - t < _rate_window]
    if len(bucket) >= _rate_max:
        return True
    bucket.append(now)
    return False


# ---------------------------------------------------------------------------
# Core converter
# ---------------------------------------------------------------------------

def convert_node(node: dict) -> str | None:
    node_type = (node.get("type") or "").lower()
    if node_type == "vless":
        return _convert_vless(node)
    logging.info("Skipping unsupported node type: %s", node_type)
    return None


def _convert_vless(node: dict) -> str | None:
    name = node.get("name", "")
    server = node.get("server", "")
    port = node.get("port", 443)
    uuid = node.get("uuid", "")
    network = (node.get("network") or "tcp").lower()
    tls = node.get("tls", False)
    servername = node.get("servername", "")
    skip_cert_verify = node.get("skip-cert-verify", False)
    client_fingerprint = node.get("client-fingerprint", "")
    flow = node.get("flow", "")
    reality_opts = node.get("reality-opts", {})
    ws_opts = node.get("ws-opts", {})
    grpc_opts = node.get("grpc-opts", {})

    if not uuid or not server:
        return None

    params = {"encryption": "none"}
    is_reality = bool(reality_opts)

    if is_reality:
        params["security"] = "reality"
        if servername:
            params["sni"] = servername
        if client_fingerprint:
            params["fp"] = client_fingerprint
        if reality_opts.get("public-key"):
            params["pbk"] = reality_opts["public-key"]
        if flow:
            params["flow"] = flow
    elif tls:
        params["security"] = "tls"
        if servername:
            params["sni"] = servername
        if client_fingerprint:
            params["fp"] = client_fingerprint

    params["type"] = network

    if skip_cert_verify:
        params["allowInsecure"] = "1"

    if network == "ws" and ws_opts:
        path = ws_opts.get("path", "")
        if path:
            params["path"] = path
        headers = ws_opts.get("headers", {})
        host = headers.get("Host", "")
        if host:
            params["host"] = host
    elif network == "grpc" and grpc_opts:
        service_name = grpc_opts.get("grpc-service-name", "")
        if service_name:
            params["serviceName"] = service_name

    query_parts = []
    for k, v in params.items():
        if v:
            query_parts.append(f"{k}={quote(str(v), safe='')}")
    query = "&".join(query_parts)

    link = f"vless://{uuid}@{server}:{port}"
    if query:
        link += f"?{query}"
    link += f"#{quote(name, safe='')}"
    return link


# ---------------------------------------------------------------------------
# Subscription fetcher
# ---------------------------------------------------------------------------

def fetch_mihomo_yaml(url: str) -> dict:
    """Fetch and parse mihomo subscription YAML with SSRF protection."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Only http/https schemes are allowed, got: {scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    if _is_private_host(hostname):
        raise ValueError(f"Access to private/internal host is forbidden: {hostname}")

    session = requests.Session()
    session.max_redirects = 5

    def _check_redirect(response, **kwargs):
        redirect_host = urlparse(response.headers.get("Location", "")).hostname
        if redirect_host and _is_private_host(redirect_host):
            raise requests.RequestException(f"Redirect to private host forbidden: {redirect_host}")

    session.hooks["response"].append(_check_redirect)

    resp = session.get(url, timeout=15, stream=True)
    resp.raise_for_status()

    # Read with size limit
    body = b""
    for chunk in resp.iter_content(8192):
        body += chunk
        if len(body) > MAX_CONTENT_LENGTH:
            raise ValueError(f"Response body exceeds {MAX_CONTENT_LENGTH} bytes")

    return yaml.safe_load(body.decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Conversion entrypoints
# ---------------------------------------------------------------------------

def convert_to_dae_nodes(yaml_data: dict) -> list[str]:
    proxies = yaml_data.get("proxies", [])
    converted: list[str] = []
    for node in proxies:
        link = convert_node(node)
        if link:
            converted.append(link)
    return converted


def convert_to_dae_config(yaml_data: dict) -> str:
    lines: list[str] = []
    lines.append("# Auto-generated by subscription-convert")
    lines.append("")
    lines.append("node {")
    for link in convert_to_dae_nodes(yaml_data):
        lines.append(f"    '{link}'")
    lines.append("}")
    lines.append("")
    lines.append("group {")
    lines.append("    proxy {")
    lines.append("        policy: min_moving_avg")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("routing {")
    lines.append("    dip(geoip:private) -> direct")
    lines.append("    dip(geoip:cn) -> direct")
    lines.append("    domain(geosite:cn) -> direct")
    lines.append("    fallback: proxy")
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/convert", methods=["GET", "POST"])
def convert():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()

    if _rate_limit(client_ip):
        return jsonify({"error": "Too many requests, please try again later."}), 429

    url = (request.args.get("url") or "").strip() or (request.form.get("url") or "").strip()
    output_fmt = ((request.args.get("fmt") or "").strip().lower()
                  or (request.form.get("fmt") or "").strip().lower()
                  or "plain")

    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    logging.info("Convert request from %s: format=%s url_prefix=%s",
                 client_ip, output_fmt, url[:80])

    try:
        yaml_data = fetch_mihomo_yaml(url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except requests.RequestException as e:
        logging.warning("Fetch error from %s: %s", client_ip, str(e)[:200])
        return jsonify({"error": f"Failed to fetch subscription: {e}"}), 502
    except yaml.YAMLError:
        return jsonify({"error": "Failed to parse YAML from subscription"}), 400

    try:
        nodes = convert_to_dae_nodes(yaml_data)
    except Exception:
        logging.exception("Conversion error")
        return jsonify({"error": "Internal conversion error"}), 500

    logging.info("Converted %d nodes for %s", len(nodes), client_ip)

    if output_fmt == "json":
        return jsonify({"nodes": nodes, "count": len(nodes)})
    if output_fmt == "dae":
        return Response(convert_to_dae_config(yaml_data), mimetype="text/plain")
    return Response("\n".join(nodes) + "\n", mimetype="text/plain")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
