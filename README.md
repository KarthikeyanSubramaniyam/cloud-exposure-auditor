# Cloud Perimeter Exposure & Public Asset Auditor

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Attack Surface Management (ASM)  
**Tech Stack**: `Python 3.10+ · Attack Surface Management · Network Auditing · Perimeter Defense`  

Perimeter security scanner auditing cloud resource inventories to detect publicly accessible databases, storage buckets, and management interfaces.

---

## 🎯 The Problem It Solves

Accidental exposure of internal assets to the public internet is the leading cause of cloud data breaches. Organizations need continuous validation of their external perimeter.

---

## ⚙️ How the Engine Works

1. **Asset Inventory Ingestion**: Ingests normalized configuration snapshots across multi-service cloud assets (S3, RDS, EC2, ELB).
2. **Perimeter Boundary Check**: Inspects resource visibility flags (`PubliclyAccessible`, `BlockPublicAcls`, `IgnorePublicAcls`).
3. **Public Network Binding Analysis**: Checks whether resources are assigned Public IP addresses or Elastic IPs within public subnets.
4. **Ingress Rule Validation**: Cross-references asset security groups for `0.0.0.0/0` exposure on ports 80, 443, 22, 3389, and database ports.
5. **Exposure Scoring**: Calculates public risk scores based on asset data classification and open port exposure.

---

## 🚀 Key Capabilities

- Identifies publicly accessible RDS database instances and Aurora clusters
- Detects S3 buckets lacking S3 Public Access Block settings
- Flags directly exposed EC2 instances with public IPs on administrative ports
- Generates executive perimeter risk summaries and containment commands

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
