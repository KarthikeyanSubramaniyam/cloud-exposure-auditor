# cloud-exposure-auditor

Audit AWS inventory JSON for public network access and missing storage protections.

## Run

Requires Python 3.10+ on Windows, Linux or macOS. No dependencies.

```bash
python scanner.py sample.json
python scanner.py sample.json --output report.json --fail-on-high
python -m unittest -v
```

Exit codes: 0 = completed, 1 = high findings with --fail-on-high, 2 = invalid input or I/O failure.

## Scope

Input: SecurityGroups from AWS EC2 describe-security-groups, plus optional Buckets containing Name and PublicAccessBlock collected separately from S3. Checks IPv4/IPv6 public ingress and bucket public access protections. Does not determine effective reachability or account-level S3 restrictions.

Reports include severity, resource, check, detail and remediation. No cloud credentials are needed; these tools inspect local JSON only. A clean report means none of the implemented checks matched, not that the cloud account is secure. Treat inventory and Terraform plans as sensitive; do not commit real account data. Sample data is fictional.

## Publish

```powershell
git init
git add .
git commit -m "Initial cloud security scanner"
gh repo create cloud-exposure-auditor --public --source . --remote origin --push
```

