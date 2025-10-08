#!/usr/bin/env python3
"""
whois_cli.py - simple WHOIS CLI tool
"""

import argparse
import socket
import sys
import json
import re
from typing import Optional, Dict, Any, List
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_WHOIS_PORT = 43
BUFFER_SIZE = 4096
DEFAULT_TIMEOUT = 8.0

try:
    import whois as pywhois
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
    try:
        resp = whois_query_server(tld, "whois.iana.org", timeout=timeout)
    except Exception:
        return None
    m = re.search(r"whois:\s*(\S+)", resp, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None

def smart_whois(domain: str, server: Optional[str] = None, port: int = DEFAULT_WHOIS_PORT, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    domain = domain.strip()
    out: Dict[str, Any] = {"query": domain, "server_used": None, "raw": None, "error": None}

    if HAVE_PYWHOIS and server is None:
        try:
            w = pywhois.whois(domain)
            d = {k: v for k, v in (getattr(w, "__dict__", {}) or {}).items()}
            out["server_used"] = "python-whois"
            out["parsed"] = d
            return out
        except Exception as e:
            out["error"] = f"python-whois failed: {e}"

    server_to_use = server
    if not server_to_use:
        parts = domain.lower().split(".")
        if len(parts) < 2:
            server_to_use = "whois.iana.org"
        else:
            tld = parts[-1]
            srv = find_whois_server_for_tld(tld, timeout=timeout)
            if srv:
                server_to_use = srv
            else:
                if tld in ("com", "net"):
                    server_to_use = "whois.verisign-grs.com"
                elif tld == "id" or domain.endswith(".sch.id"):
                    server_to_use = "whois.pandi.or.id"
                else:
                    server_to_use = "whois.iana.org"

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

def print_clean(raw: str):
    """Cetak hasil WHOIS bersih dan rapi"""
    if not raw:
        print(Fore.RED + "No WHOIS data.")
        return
    clean_raw = re.sub(r'[\r]+', '', raw)
    clean_raw = re.sub(r'\n\s*\n+', '\n', clean_raw.strip())
    for line in clean_raw.split("\n"):
        print("  " + Fore.WHITE + line.strip())

def main():
    print(Fore.CYAN + BANNER)
    args = parse_args()
    domains = args.domains[:]
    if args.batch:
        try:
            domains += load_batch(args.batch)
        except Exception as e:
            print(Fore.RED + f"Failed to read batch file: {e}", file=sys.stderr)
            sys.exit(2)
    if not domains:
        print(Fore.YELLOW + "No domains specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    results = []
    for d in domains:
        res = smart_whois(d, server=args.server, port=args.port, timeout=args.timeout)
        results.append(res)
        if args.output == "text":
            print(Fore.GREEN + "=" * 70)
            print(Fore.YELLOW + f"Domain: {d}")
            print(Fore.CYAN + f"Server used: {res.get('server_used')}")
            if res.get("server_used_follow"):
                print(Fore.CYAN + f"Referral server used: {res.get('server_used_follow')}")
            if res.get("error"):
                print(Fore.RED + "ERROR:", res["error"])
            elif res.get("parsed"):
                print(Fore.MAGENTA + "\n--- WHOIS INFO (parsed) ---\n")
                for k, v in res["parsed"].items():
                    print(f"  {Fore.GREEN}{k:<20}{Style.RESET_ALL}: {v}")
            elif res.get("raw"):
                print(Fore.MAGENTA + "\n--- WHOIS INFO ---\n")
                print_clean(res["raw"])
            if res.get("raw_follow"):
                print(Fore.BLUE + "\n--- WHOIS (Referral) ---\n")
                print_clean(res["raw_follow"])
            print(Fore.GREEN + "=" * 70 + "\n")

    if args.output == "json":
        print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
