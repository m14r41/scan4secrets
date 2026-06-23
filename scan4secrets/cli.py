"""scan4secrets v2 CLI.

Usage examples:
  scan4secrets --path /code --report sarif json --output reports/run1
  scan4secrets --url https://target.com --threads 32 --verify --report html
  scan4secrets --path /code --rules custom-rules.yaml --fail-on high
"""

from __future__ import annotations
import argparse
import logging
import sys
from pathlib import Path
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich import box

from scan4secrets import __version__
from scan4secrets.engine.rules import load_rules
from scan4secrets.engine.scanner import scan_path, DEFAULT_SKIP_DIRS, DEFAULT_MAX_BYTES
from scan4secrets.engine.crawler import crawl_and_scan, build_session, normalize_url
from scan4secrets.engine.wordlists import seed_urls_from_wordlists, seed_urls_from_files, load_wordlists
from scan4secrets.engine.verifier import verify_findings
from scan4secrets.engine.findings import Finding, severity_at_least, suppress_generic_when_specific
from scan4secrets.reporters import write_reports


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scan4secrets",
        description="DAST + SAST secret scanner — verify findings against vendor APIs.",
    )
    p.add_argument("--version", action="version", version=f"scan4secrets {__version__}")

    src = p.add_argument_group("Input")
    src.add_argument("--path", help="local directory or file (SAST)")
    src.add_argument("--url", help="target URL (DAST)")
    src.add_argument("--stdin", action="store_true", help="read content from stdin")

    rules = p.add_argument_group("Rules")
    rules.add_argument("--rules", help="path to custom rules.yaml")
    rules.add_argument("--rule-id", nargs="+", help="only run these rule IDs")
    rules.add_argument("--disable-rule", nargs="+", default=[], help="rule IDs to disable")
    rules.add_argument("--entropy-min", type=float, help="override per-rule entropy floor")

    sast = p.add_argument_group("SAST (filesystem)")
    sast.add_argument("--exclude", nargs="+", default=[], help="extra glob patterns to exclude")
    sast.add_argument("--exclude-dir", nargs="+", default=[], help="extra directory names to skip")
    sast.add_argument("--max-size", default=str(DEFAULT_MAX_BYTES), help="skip files larger than (bytes or e.g. 10M)")

    dast = p.add_argument_group("DAST (web)")
    dast.add_argument("--threads", type=int, default=16)
    dast.add_argument("--timeout", type=int, default=10)
    dast.add_argument("--max-urls", type=int, default=2000,
                      help="max URLs to fetch per run (default 2000; large enough to crawl bundled wordlists + discovered links)")
    dast.add_argument("--max-depth", type=int, default=3)
    dast.add_argument("--user-agent", help="override User-Agent")
    dast.add_argument("--header", action="append", default=[], metavar="K:V", help="add request header (repeatable)")
    dast.add_argument("--cookie", help="cookie string")
    dast.add_argument("--proxy", help="http(s) proxy URL")
    dast.add_argument("--insecure", action="store_true", help="skip TLS verification")
    dast.add_argument("--strict-host", action="store_true", help="restrict crawl to exact start host (default: same eTLD+1)")
    dast.add_argument("--no-sourcemaps", action="store_true", help="skip parsing .js.map files")
    dast.add_argument("--no-js-endpoints", action="store_true", help="skip extracting endpoints from JS sources")
    dast.add_argument("--wordlist", nargs="+", metavar="FILE",
                      help="path(s) to user wordlist file(s). When given, REPLACES the bundled wordlists.")
    dast.add_argument("--wordlist-only", nargs="+", metavar="NAME",
                      help="restrict bundled wordlists to these stems (e.g. common env wordpress). Ignored if --wordlist is given.")
    dast.add_argument("--no-wordlist", action="store_true",
                      help="disable wordlist seeding entirely")

    verify = p.add_argument_group("Verification")
    verify.add_argument("--verify", action="store_true", help="live-verify findings against vendor APIs")
    verify.add_argument("--verify-timeout", type=int, default=5)

    out = p.add_argument_group("Output")
    out.add_argument("--report", nargs="+", default=["html", "json"],
                     choices=["sarif", "json", "jsonl", "csv", "html", "excel", "pdf"])
    out.add_argument("--output", default="scan4secrets-report",
                     help="output base path (extension added per format)")
    out.add_argument("--mask", action="store_true", help="redact secret values in output (default: show raw values for vendor PoC)")

    log = p.add_argument_group("Logging / CI")
    log.add_argument("--quiet", action="store_true")
    log.add_argument("--verbose", action="store_true")
    log.add_argument("--debug", action="store_true")
    log.add_argument("--no-color", action="store_true")
    log.add_argument("--fail-on", choices=["info","low","medium","high","critical"], default=None,
                     help="exit 1 if any finding >= this severity")
    log.add_argument("--keep-generic", action="store_true",
                     help="don't suppress generic-rule duplicates when a vendor-specific rule fired on the same value")
    return p


def _parse_size(s: str) -> int:
    s = str(s).strip().upper()
    units = {"K": 1024, "M": 1024**2, "G": 1024**3}
    if s and s[-1] in units:
        return int(float(s[:-1]) * units[s[-1]])
    return int(s)


def _parse_headers(items):
    out = {}
    for it in items:
        if ":" in it:
            k, _, v = it.partition(":")
            out[k.strip()] = v.strip()
    return out


def _filter_rules(rules, ids, disabled, entropy_override):
    if ids:
        wanted = set(ids)
        rules = [r for r in rules if r.id in wanted]
    if disabled:
        bad = set(disabled)
        rules = [r for r in rules if r.id not in bad]
    if entropy_override is not None:
        for r in rules:
            r.entropy_min = entropy_override
    return rules


def _print_summary(findings, console: Console):
    counts = Counter(f.severity for f in findings)
    tbl = Table(title="Scan summary", box=box.SQUARE, show_header=True)
    tbl.add_column("Severity")
    tbl.add_column("Count", justify="right")
    for s in ("critical", "high", "medium", "low", "info"):
        tbl.add_row(s, str(counts.get(s, 0)))
    tbl.add_row("[bold]TOTAL", f"[bold]{len(findings)}")
    console.print(tbl)


def _print_findings(findings, console: Console, *, mask: bool = False):
    if not findings:
        return
    tbl = Table(box=box.SIMPLE, show_lines=False, header_style="bold")
    tbl.add_column("SEV", width=8)
    tbl.add_column("Rule", width=28)
    tbl.add_column("V", width=3, justify="center")
    tbl.add_column("Where", overflow="fold")
    tbl.add_column("Secret (redacted)" if mask else "Secret", overflow="fold")
    style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    for f in findings:
        vmark = "[green]Y[/green]" if f.verified is True else "[dim]-[/dim]" if f.verified is None else "[dim]n[/dim]"
        tbl.add_row(
            f"[{style.get(f.severity,'')}]{f.severity}[/]",
            f.rule_id,
            vmark,
            f"{f.file}:{f.line}",
            f.secret_redacted if mask else f.secret,
        )
    console.print(tbl)


def main(argv=None) -> int:
    args = _parser().parse_args(argv)

    level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s %(message)s")

    if not (args.path or args.url or args.stdin):
        print("error: --path, --url, or --stdin required", file=sys.stderr)
        return 2

    console = Console(quiet=args.quiet, no_color=args.no_color)

    rules = load_rules(args.rules)
    rules = _filter_rules(rules, args.rule_id, args.disable_rule, args.entropy_min)
    if not args.quiet:
        console.print(f"[bold]scan4secrets v{__version__}[/] — {len(rules)} rules loaded")

    findings = []

    if args.stdin:
        from scan4secrets.engine.scanner import scan_text
        from scan4secrets.engine.rules import KeywordIndex
        idx = KeywordIndex(rules)
        text = sys.stdin.read()
        findings.extend(scan_text(text, "<stdin>", rules, idx))

    if args.path:
        if not args.quiet:
            console.print(f"[bold cyan]SAST[/] scanning {args.path}")
        exclude_dirs = DEFAULT_SKIP_DIRS | set(args.exclude_dir)
        findings.extend(scan_path(
            Path(args.path), rules,
            exclude_dirs=exclude_dirs,
            exclude_globs=args.exclude,
            max_bytes=_parse_size(args.max_size),
        ))

    if args.url:
        if not args.quiet:
            console.print(f"[bold cyan]DAST[/] crawling {args.url}")
        session = build_session(
            user_agent=args.user_agent or None,
            headers=_parse_headers(args.header),
            cookie=args.cookie,
            proxy=args.proxy,
            verify_tls=not args.insecure,
            timeout=args.timeout,
        )
        extra_seeds = []
        if args.no_wordlist:
            scope_label = "disabled"
        elif args.wordlist:
            extra_seeds = seed_urls_from_files(normalize_url(args.url), args.wordlist)
            scope_label = f"user:{','.join(args.wordlist)}"
        elif args.wordlist_only:
            extra_seeds = seed_urls_from_wordlists(normalize_url(args.url), only=args.wordlist_only)
            scope_label = f"bundled:{','.join(args.wordlist_only)}"
        else:
            extra_seeds = seed_urls_from_wordlists(normalize_url(args.url))
            scope_label = "bundled:all"
        if not args.quiet and not args.no_wordlist:
            console.print(f"[dim]wordlist ({scope_label}) seeded {len(extra_seeds)} candidate URLs[/]")
        findings.extend(crawl_and_scan(
            normalize_url(args.url), rules,
            session=session,
            max_urls=args.max_urls,
            max_depth=args.max_depth,
            threads=args.threads,
            timeout=args.timeout,
            strict_host=args.strict_host,
            parse_sourcemaps=not args.no_sourcemaps,
            extract_js_endpoints=not args.no_js_endpoints,
            extra_seeds=extra_seeds,
        ))

    # dedupe across SAST + DAST
    seen = set()
    deduped = []
    for f in findings:
        if f.dedup_key() in seen:
            continue
        seen.add(f.dedup_key())
        deduped.append(f)
    findings = deduped

    # noise reduction: suppress generic rules when a specific vendor rule fired on the same value
    if not args.keep_generic:
        before = len(findings)
        findings = suppress_generic_when_specific(findings)
        if before > len(findings) and not args.quiet:
            console.print(f"[dim]suppressed {before - len(findings)} generic-rule duplicates[/]")

    if args.verify and findings:
        if not args.quiet:
            console.print(f"[bold]Verifying[/] {sum(1 for f in findings if any(r.id == f.rule_id and r.verify for r in rules))} candidates...")
        verify_findings(findings, rules, timeout=args.verify_timeout)

    if not args.quiet:
        _print_findings(findings, console, mask=args.mask)
        _print_summary(findings, console)

    if findings:
        out_base = Path(args.output)
        out_base.parent.mkdir(parents=True, exist_ok=True)
        written = write_reports(findings, out_base, args.report, unsafe_show=not args.mask)
        if not args.quiet:
            for fmt, p in written.items():
                console.print(f"[green]+[/] {fmt.upper():6s} -> {p}")
    elif not args.quiet:
        console.print("[green]No secrets found.[/]")

    if args.fail_on and any(severity_at_least(f.severity, args.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
