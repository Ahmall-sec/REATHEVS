#!/usr/bin/env python3
"""
whois_cli.py - simple WHOIS CLI tool

Usage examples:
  python3 whois_cli.py example.com
  python3 whois_cli.py -o json example.com
  python3 whois_cli.py -b domains.txt
  python3 whois_cli.py -s whois.crsnic.net example.com
"""

import argparse
import socket
import sys
import json
import re
from typing import Optional, Tuple, Dict, Any, List

DEFAULT_WHOIS_PORT = 43
BUFFER_SIZE = 4096
DEFAULT_TIMEOUT = 8.0

# Try to use python-whois if installed
try:
    import whois as pywhois  # pip install python-whois
    HAVE_PYWHOIS = True
except Exception:
    HAVE_PYWHOIS = False


# =======================================================
# ASCII Banner
# =======================================================
BANNER = r"""
██████╗ ███████╗ █████╗ ████████╗██╗  ██╗███████╗██╗   ██╗███████╗
██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝
██████╔╝█████╗  ███████║   ██║   ███████║█████╗  ██║   ██║███████╗
██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══╝  ╚██╗ ██╔╝╚════██║
██║  ██║███████╗██║  ██║   ██║   ██║  ██║███████╗ ╚████╔╝ ███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝
                        Whois CLI by DeathEye
====================================================================
"""


def whois_query_server(query: str, server: str, port: int = DEFAULT_WHOIS_PORT, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Query a WHOIS server using raw socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, port))
        s.sendall((query + "\r\n").encode('utf-8', errors='ignore'))
        data_parts = []
        while True:
            chunk = s.recv(BUFFER_SIZE)
            if not chunk:
                break
            data_parts.append(chunk)
        return b"".join(data_parts).decode('utf-8', errors='ignore')
    finally:
        s.close()


def find_whois_server_for_tld(tld: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[str]:
    """Ask whois.iana.org for the authoritative whois server for a TLD."""
    try:
        resp = whois_query_server(tld, "whois.iana.org", timeout=timeout)
    except Exception:
        return None
    m = re.search(r"whois:\s*(\S+)", resp, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def smart_whois(domain: str, server: Optional[str] = None, port: int = DEFAULT_WHOIS_PORT, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Perform WHOIS lookup with a simple server discovery fallback."""
    domain = domain.strip()
    out: Dict[str, Any] = {"query": domain, "server_used": None, "raw": None, "error": None}

    if HAVE_PYWHOIS and server is None:
        try:
            w = pywhois.whois(domain)
            d = {k: v for k, v in (getattr(w, "__dict__", {}) or {}).items()}
            out["server_used"] = "python-whois"
            out["raw"] = str(d)
            out["parsed"] = d
            return out
        except Exception as e:
            out["error"] = f"python-whois failed: {e}"

    server_to_use = server
    if server_to_use is None:
        parts = domain.lower().split(".")
        if len(parts) < 2:
            server_to_use = "whois.iana.org"
        else:
            tld = parts[-1]
            srv = find_whois_server_for_tld(tld, timeout=timeout)
            server_to_use = srv or ("whois.verisign-grs.com" if tld in ("com", "net") else "whois.iana.org")

    out["server_used"] = server_to_use
    try:
        raw = whois_query_server(domain, server_to_use, port=port, timeout=timeout)
        out["raw"] = raw
        m = re.search(r"Whois Server:\s*(\S+)", raw, re.IGNORECASE)
        if m:
            ref = m.group(1).strip()
            if ref and ref != server_to_use:
                try:
                    raw2 = whois_query_server(domain, ref, port=port, timeout=timeout)
                    out["raw_follow"] = raw2
                    out["server_used_follow"] = ref
                except Exception as e:
                    out.setdefault("notes", []).append(f"follow referral failed: {e}")
        return out
    except Exception as exc:
        out["error"] = str(exc)
        return out


def parse_args():
    p = argparse.ArgumentParser(description="Simple WHOIS CLI tool")
    p.add_argument("domains", nargs="*", help="Domain(s) to query e.g. example.com")
    p.add_argument("-s", "--server", help="WHOIS server override")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_WHOIS_PORT)
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("-o", "--output", choices=("text", "json"), default="text")
    p.add_argument("-b", "--batch", help="File with list of domains")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    p.add_argument("--no-referral", action="store_true", help="Disable referral follow")
    return p.parse_args()


def load_batch(file_path: str) -> List[str]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def main():
    print(BANNER)  # <── Banner ditampilkan di awal
    args = parse_args()
    domains = args.domains[:]
    if args.batch:
        try:
            domains += load_batch(args.batch)
        except Exception as e:
            print(f"Failed to read batch file: {e}", file=sys.stderr)
            sys.exit(2)
    if not domains:
        print("No domains specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    results = []
    for d in domains:
        if args.quiet and args.output == "text":
            res = smart_whois(d, server=args.server, port=args.port, timeout=args.timeout)
            print(res.get("raw", ""))
            continue
        res = smart_whois(d, server=args.server, port=args.port, timeout=args.timeout)
        if args.no_referral:
            res.pop("raw_follow", None)
            res.pop("server_used_follow", None)
        results.append(res)
        if args.output == "text":
            print("=" * 70)
            print(f"Domain: {d}")
            print(f"Server used: {res.get('server_used')}")
            if res.get("server_used_follow"):
                print(f"Referral server used: {res.get('server_used_follow')}")
            if res.get("error"):
                print("ERROR:", res["error"])
            if res.get("raw"):
                print("\n--- RAW WHOIS ---\n")
                print(res["raw"])
            if res.get("raw_follow"):
                print("\n--- RAW WHOIS (follow referral) ---\n")
                print(res["raw_follow"])
            print("=" * 70 + "\n")

    if args.output == "json":
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
