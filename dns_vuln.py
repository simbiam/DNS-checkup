#!/usr/bin/env python3
"""
DNS Zone Transfer Vulnerability Scanner
========================================
Author  : Cybersecurity Engineer
Purpose : Detect domains vulnerable to DNS zone transfer (AXFR) attacks.
Usage   :
  Single domain  -> python dns_zone_transfer.py -d example.com
  Domain list    -> python dns_zone_transfer.py -f domains.txt
  With output    -> python dns_zone_transfer.py -f domains.txt -o results.txt
"""

import argparse
import sys
import os
from datetime import datetime

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
except ImportError:
    print("[!] dnspython is not installed. Run: pip install dnspython")
    sys.exit(1)


# ─────────────────────────────────────────────
# ANSI colour helpers (disabled on Windows)
# ─────────────────────────────────────────────
USE_COLOR = sys.platform != "win32"

def red(s):    return f"\033[91m{s}\033[0m" if USE_COLOR else s
def green(s):  return f"\033[92m{s}\033[0m" if USE_COLOR else s
def yellow(s): return f"\033[93m{s}\033[0m" if USE_COLOR else s
def cyan(s):   return f"\033[96m{s}\033[0m" if USE_COLOR else s
def bold(s):   return f"\033[1m{s}\033[0m"  if USE_COLOR else s


# ─────────────────────────────────────────────
# Status constants  (single source of truth)
# ─────────────────────────────────────────────
VULNERABLE     = "VULNERABLE"
NOT_VULNERABLE = "NOT VULNERABLE"


# ─────────────────────────────────────────────
# Core functions
# ─────────────────────────────────────────────

def get_nameservers(domain: str) -> list[str]:
    """
    Query NS records for a domain and return a list of nameserver hostnames.
    Returns an empty list if the lookup fails.
    """
    nameservers = []
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for rdata in answers:
            ns = str(rdata.target).rstrip(".")
            nameservers.append(ns)
    except dns.resolver.NXDOMAIN:
        print(f"  {red('[!]')} Domain does not exist: {domain}")
    except dns.resolver.NoAnswer:
        print(f"  {yellow('[!]')} No NS records found for: {domain}")
    except dns.resolver.NoNameservers:
        print(f"  {yellow('[!]')} No reachable nameservers for: {domain}")
    except dns.exception.DNSException as exc:
        print(f"  {yellow('[!]')} NS lookup error for {domain}: {exc}")
    return nameservers


def attempt_zone_transfer(domain: str, nameserver: str, timeout: int = 10):
    """
    Attempt an AXFR (zone transfer) from a single nameserver.

    Returns
    -------
    (success: bool, records: list[str] | None, error: str | None)
    """
    try:
        # Resolve the NS hostname to an IP address first
        ns_answers = dns.resolver.resolve(nameserver, "A")
        ns_ip = str(ns_answers[0])

        # Perform AXFR
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
        records = []
        for name, node in zone.nodes.items():
            rdatasets = node.rdatasets
            for rdataset in rdatasets:
                for rdata in rdataset:
                    records.append(f"  {name}.{domain}  {rdataset.ttl}  "
                                   f"{dns.rdatatype.to_text(rdataset.rdtype)}  {rdata}")
        return True, records, None

    except dns.resolver.NXDOMAIN:
        return False, None, "Nameserver hostname not found"
    except dns.resolver.NoAnswer:
        return False, None, "Could not resolve nameserver IP"
    except dns.exception.FormError:
        return False, None, "AXFR refused or malformed response"
    except ConnectionRefusedError:
        return False, None, "Connection refused"
    except TimeoutError:
        return False, None, "Connection timed out"
    except EOFError:
        return False, None, "Connection closed (transfer denied)"
    except Exception as exc:          # Catch-all for unexpected DNS errors
        return False, None, str(exc)


def check_domain(domain: str, timeout: int = 10) -> dict:
    """
    Full vulnerability check for one domain.

    Returns a result dict:
      {
        "domain"     : str,
        "nameservers": [str, ...],
        "vulnerable" : bool,
        "details"    : [ { "ns": str, "vulnerable": bool, "records": [...] | None, "error": str | None } ]
      }
    """
    domain = domain.strip().lower()
    result = {
        "domain"      : domain,
        "nameservers" : [],
        "vulnerable"  : False,
        "details"     : [],
    }

    print(f"\n{bold(cyan('='*60))}")
    print(f"  {bold('Target:')} {domain}")
    print(f"{bold(cyan('='*60))}")

    nameservers = get_nameservers(domain)
    if not nameservers:
        print(f"  {red('[SKIP]')} Cannot proceed – no nameservers found.")
        return result

    result["nameservers"] = nameservers
    print(f"  {bold('Nameservers found:')} {', '.join(nameservers)}\n")

    for ns in nameservers:
        print(f"  {yellow('[*]')} Trying AXFR on {ns} …", end=" ", flush=True)
        success, records, error = attempt_zone_transfer(domain, ns, timeout)

        ns_detail = {"ns": ns, "vulnerable": success, "records": records, "error": error}
        result["details"].append(ns_detail)

        if success:
            result["vulnerable"] = True
            print(green(VULNERABLE))
            print(f"  {green('[+]')} Zone transfer succeeded! "
                  f"{len(records)} record(s) retrieved:")
            for rec in records[:20]:          # Print up to 20 records
                print(f"    {rec}")
            if len(records) > 20:
                print(f"    … and {len(records) - 20} more record(s).")
        else:
            print(red(NOT_VULNERABLE))
            print(f"  {red('[-]')} Transfer denied: {error}")

    verdict = green(f"⚠  {VULNERABLE}") if result["vulnerable"] else red(f"✔  {NOT_VULNERABLE}")
    print(f"\n  {bold('Result:')} {verdict}")
    return result


def format_summary(results: list[dict]) -> str:
    """Build a human-readable summary table."""
    lines = [
        "",
        "=" * 60,
        "  SCAN SUMMARY",
        "=" * 60,
        f"  {'DOMAIN':<35} {'STATUS':<20} {'NS COUNT'}",
        "-" * 60,
    ]
    vuln_count = 0
    for r in results:
        status = VULNERABLE if r["vulnerable"] else NOT_VULNERABLE
        lines.append(f"  {r['domain']:<35} {status:<20} {len(r['nameservers'])}")
        if r["vulnerable"]:
            vuln_count += 1
    lines += [
        "-" * 60,
        f"  Total scanned : {len(results)}",
        f"  Vulnerable    : {vuln_count}",
        f"  Safe          : {len(results) - vuln_count}",
        "=" * 60,
        "",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────
# Entry point  (refactored for low complexity)
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="DNS Zone Transfer (AXFR) Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python dns_zone_transfer.py -d zonetransfer.me\n"
            "  python dns_zone_transfer.py -f domains.txt\n"
            "  python dns_zone_transfer.py -f domains.txt -o report.txt -t 15\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain",
                       metavar="DOMAIN",
                       help="Single domain to test (e.g. example.com)")
    group.add_argument("-f", "--file",
                       metavar="FILE",
                       help="Path to a text file containing one domain per line")
    parser.add_argument("-o", "--output",
                        metavar="FILE",
                        help="Optional output file to save results")
    parser.add_argument("-t", "--timeout",
                        type=int,
                        default=10,
                        metavar="SECONDS",
                        help="Timeout for each AXFR attempt (default: 10)")
    return parser.parse_args()


def load_domains_from_file(filepath: str) -> list[str]:
    """Load and return non-empty, non-comment lines from a domain list file."""
    if not os.path.isfile(filepath):
        print(f"{red('[!]')} File not found: {filepath}")
        sys.exit(1)
    with open(filepath, "r") as fh:
        domains = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    if not domains:
        print(f"{yellow('[!]')} No domains found in file: {filepath}")
        sys.exit(1)
    return domains


def print_banner(timeout: int) -> None:
    """Print the startup banner."""
    # ── NEW helper (extracted from main) ──────────────────────────────────
    banner = f"""
{cyan(bold('╔══════════════════════════════════════════════════════╗'))}
{cyan(bold('║      DNS Zone Transfer Vulnerability Scanner         ║'))}
{cyan(bold('║      AXFR Attack Detection Tool                      ║'))}
{cyan(bold('╚══════════════════════════════════════════════════════╝'))}
  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Timeout : {timeout}s per AXFR attempt
"""
    print(banner)


def collect_domains(args) -> list[str]:
    """Return the list of domains to scan based on CLI arguments."""
    # ── NEW helper (extracted from main) ──────────────────────────────────
    if args.domain:
        return [args.domain]
    domains = load_domains_from_file(args.file)
    print(f"  {bold('Domains loaded:')} {len(domains)}")
    return domains


def scan_domains(domains: list[str], timeout: int) -> list[dict]:
    """Run check_domain() over every domain and return all results."""
    # ── NEW helper (extracted from main) ──────────────────────────────────
    return [check_domain(domain, timeout=timeout) for domain in domains]


def write_report(results: list[dict], summary: str, output_path: str) -> None:
    """Save scan results and summary to a text file."""
    # ── NEW helper (extracted from main) ──────────────────────────────────
    with open(output_path, "w") as fh:
        fh.write("DNS Zone Transfer Scan Report\n")
        fh.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for r in results:
            _write_domain_block(fh, r)
        fh.write(summary)
    print(f"  {green('[+]')} Report saved to: {output_path}")


def _write_domain_block(fh, r: dict) -> None:
    """Write one domain's result block to an open file handle."""
    # ── NEW helper (extracted from write_report to keep it simple) ────────
    fh.write(f"Domain     : {r['domain']}\n")
    fh.write(f"Vulnerable : {'YES' if r['vulnerable'] else 'NO'}\n")
    fh.write(f"Nameservers: {', '.join(r['nameservers']) or 'N/A'}\n")
    for d in r["details"]:
        status = VULNERABLE if d["vulnerable"] else NOT_VULNERABLE
        fh.write(f"  NS: {d['ns']} -> {status}")
        if d["error"]:
            fh.write(f" ({d['error']})")
        fh.write("\n")
        if d["records"]:
            for rec in d["records"]:
                fh.write(f"    {rec}\n")
    fh.write("\n" + "-" * 60 + "\n\n")


def main() -> None:
    """
    Entry point — now intentionally thin.
    Each logical step lives in its own helper so cognitive complexity stays low.
    """
    # ── CHANGED: was one big function (complexity 30), now ≤ 5 ────────────
    args = parse_args()
    print_banner(args.timeout)

    domains     = collect_domains(args)
    all_results = scan_domains(domains, args.timeout)
    summary     = format_summary(all_results)

    print(summary)

    if args.output:
        write_report(all_results, summary, args.output)


if __name__ == "__main__":
    main()
