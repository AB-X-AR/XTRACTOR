# XTRACTOR - Universal HTML/JS/CSS/Logic Vulnerability Term Scanner
# Author: Max | License: MIT

import argparse
import requests
import re
import os
import json
from bs4 import BeautifulSoup
from termcolor import colored


def load_vuln_maps(args):
    maps = {}
    if args.html:
        maps.update(load_map_file("VULN_MAP_HTML.json"))
    if args.js:
        maps.update(load_map_file("VULN_MAP_JS.json"))
    if args.css:
        maps.update(load_map_file("VULN_MAP_CSS.json"))
    if args.a:
        for extra in ["VULN_MAP_PHP.json", "VULN_MAP_SQL.json", "VULN_MAP_HEADERS.json", 
                      "VULN_MAP_JSON.json", "VULN_MAP_REACT.json", "VULN_MAP_NODE.json", 
                      "VULN_MAP_AJAX.json", "VULN_MAP_CLOUD.json", "VULN_MAP_ALL.json"]:
            if os.path.exists(extra):
                maps.update(load_map_file(extra))
    return maps


def load_map_file(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load {filename}: {e}")
        return {}


def fetch_html(url):
    try:
        res = requests.get(url, timeout=10)
        return res.text, res.headers
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return "", {}


def scan_html(content, vuln_map, strict=False):
    results = []
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("//", "/*", "*", "#")):
            continue
        for term, desc in vuln_map.items():
            pattern = re.compile(rf'\b{re.escape(term)}\b')
            if pattern.search(line):
                if strict and term not in line.split():
                    continue
                highlight = colored(term, 'green')
                vuln = colored(desc, 'light_red')
                results.append(f"{i}. {highlight} in line {i} : {vuln}")
    return results


def check_headers(headers):
    issues = []
    expected = {
        "Content-Security-Policy": "Prevents XSS and content injection",
        "X-Frame-Options": "Protects against Clickjacking",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Strict-Transport-Security": "Enforces HTTPS",
        "Access-Control-Allow-Origin": "CORS Misconfiguration"
    }
    for h, reason in expected.items():
        if h not in headers:
            issues.append(colored(f"Missing Header: {h} - {reason}", 'yellow'))
    return issues


def run_scan(targets, vuln_map, output_file, strict, output_json=False, output_html=False):
    output_lines = []
    report = {}

    for url in targets:
        print(f"\n---\nScanning: {url}")
        html, headers = fetch_html("http://" + url if not url.startswith("http") else url)
        issues = scan_html(html, vuln_map, strict=strict)
        header_issues = check_headers(headers)

        combined_issues = issues + header_issues

        if combined_issues:
            report[url] = combined_issues
            output_lines.append(f"Possible HTML Terms found in : {url}")
            for issue in combined_issues:
                print(issue)
                output_lines.append(issue)
        else:
            print(colored("No issues found", "cyan"))

        output_lines.append("####")

    if output_file:
        try:
            if output_json:
                with open(output_file.replace(".txt", ".json"), 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2)
            elif output_html:
                with open(output_file.replace(".txt", ".html"), 'w', encoding='utf-8') as f:
                    html_report = "<html><body><h1>XTRACTOR Report</h1><pre>" + "\n".join(output_lines) + "</pre></body></html>"
                    f.write(html_report)
            else:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(output_lines))
            print(f"\n[+] Report saved to {output_file}")
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="XTRACTOR - HTML/JS/CSS Vulnerability Term Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True
    )
    parser.add_argument("-html", action='store_true', help="Scan HTML terms")
    parser.add_argument("-js", action='store_true', help="Scan JavaScript terms")
    parser.add_argument("-css", action='store_true', help="Scan CSS terms")
    parser.add_argument("-a", action='store_true', help="Scan all additional languages and logic maps")
    parser.add_argument("-u", help="Single URL to scan")
    parser.add_argument("-U", help="File containing list of URLs")
    parser.add_argument("-f", help="Local HTML file to scan")
    parser.add_argument("-o", help="Output file to save results")
    parser.add_argument("--strict", action='store_true', help="Suppress low-confidence results")
    parser.add_argument("--json", action='store_true', help="Output report in JSON format")
    parser.add_argument("--html", action='store_true', help="Output report in HTML format")
    args = parser.parse_args()

    vuln_maps = load_vuln_maps(args)
    targets = []

    if args.f:
        try:
            with open(args.f, 'r', encoding='utf-8') as f:
                content = f.read()
                issues = scan_html(content, vuln_maps, strict=args.strict)
                if issues:
                    for issue in issues:
                        print(issue)
                    if args.o:
                        run_scan(["localfile"], vuln_maps, args.o, args.strict, args.json, args.html)
                else:
                    print(colored("No issues found in local file", "cyan"))
        except Exception as e:
            print(f"[!] Error reading file: {e}")
        return

    if args.u:
        targets = [args.u.strip()]
    elif args.U:
        try:
            with open(args.U, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return
    else:
        print("[!] No URL, file or raw HTML input provided")
        return

    run_scan(targets, vuln_maps, args.o, args.strict, args.json, args.html)


if __name__ == '__main__':
    main()
