"""Audit AWS inventory JSON for public network access and missing storage protections."""
import ipaddress

def audit(data):
    findings = []
    for group in data.get("SecurityGroups", []):
        for rule in group.get("IpPermissions", []):
            public = any(ipaddress.ip_network(r["CidrIp"], strict=False).prefixlen == 0 for r in rule.get("IpRanges", []))
            public |= any(ipaddress.ip_network(r["CidrIpv6"], strict=False).prefixlen == 0 for r in rule.get("Ipv6Ranges", []))
            if public:
                start, end = rule.get("FromPort"), rule.get("ToPort")
                sensitive = rule.get("IpProtocol") == "-1" or (start is not None and end is not None and any(start <= p <= end for p in (22, 3389, 3306, 5432, 6379, 27017)))
                findings.append({"resource": group["GroupId"], "severity": "HIGH" if sensitive else "MEDIUM", "check": "PUBLIC_INGRESS", "detail": f"Public ingress protocol={rule.get('IpProtocol')} ports={start}-{end}", "remediation": "Restrict source CIDRs to approved networks."})
    for bucket in data.get("Buckets", []):
        protection = bucket.get("PublicAccessBlock")
        if protection is None:
            findings.append({"resource": bucket["Name"], "severity": "UNKNOWN", "check": "S3_PUBLIC_ACCESS", "detail": "Public access block configuration was not supplied.", "remediation": "Collect bucket and account public access settings."})
        elif not all(protection.get(k) is True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            findings.append({"resource": bucket["Name"], "severity": "MEDIUM", "check": "S3_PUBLIC_ACCESS", "detail": "Some public access protections are disabled; this alone does not prove the bucket is public.", "remediation": "Review bucket policy, ACL and account protections."})
    return findings

import argparse
import json
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Input JSON file")
    parser.add_argument("--output", type=Path, help="Write JSON report")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 when HIGH findings exist")
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Input must be a JSON object")
        findings = audit(data)
        report = {"findings": findings, "finding_count": len(findings), "scope": "Only documented checks and supplied input are evaluated."}
        text = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(f["severity"] == "HIGH" for f in findings))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(f"Invalid input or report error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

