#!/usr/bin/env python3
"""Generate synthetic security vulnerability Jira tickets for Triage LLM training."""

import json
import random
from typing import Dict, Any

# =============================================================================
# VARIABLE 1: Expanded Vulnerability Categories
# =============================================================================

VULNERABILITY_CATEGORIES = {
    "Infrastructure (AWS)": [
        {"type": "AWS Access Key ID", "pattern": "AKIA...", "example_masked": "AKIA...7X2A"},
        {"type": "AWS Secret Access Key", "pattern": "40-char base64", "example_masked": "wJalrXUtnFEMI/K7..."},
        {"type": "AWS Session Token", "pattern": "FwoGZXIv...", "example_masked": "FwoGZXIvYXdzE..."},
    ],
    "Infrastructure (GCP/Azure)": [
        {"type": "Google API Key", "pattern": "AIza...", "example_masked": "AIzaSyD...4x2a"},
        {"type": "Google OAuth2 Client Secret", "pattern": "GOCSPX-...", "example_masked": "GOCSPX-..."},
        {"type": "GCP Service Account Key", "pattern": "JSON key file", "example_masked": '{"type":"service_account"...}'},
        {"type": "Azure Storage Account Key", "pattern": "base64 key", "example_masked": "Eby8vdM02xNO..."},
    ],
    "SaaS & Messaging": [
        {"type": "Slack Webhook URL", "pattern": "hooks.slack.com/...", "example_masked": "https://hooks.slack.com/services/T.../B.../..."},
        {"type": "Mailgun API Key", "pattern": "key-...", "example_masked": "key-3ax6..."},
        {"type": "Stripe Secret Key", "pattern": "sk_live_...", "example_masked": "sk_live_...4x2a"},
        {"type": "Twilio API Key", "pattern": "SK...", "example_masked": "SK...abcd"},
        {"type": "SendGrid API Key", "pattern": "SG....", "example_masked": "SG....xyz"},
        {"type": "Discord Bot Token", "pattern": "NjE...", "example_masked": "NjE3..."},
    ],
    "Code Repositories": [
        {"type": "GitHub Personal Access Token (PAT)", "pattern": "ghp_...", "example_masked": "ghp_...abcd1234"},
        {"type": "GitLab Runner Token", "pattern": "glrt-...", "example_masked": "glrt-..."},
        {"type": "Bitbucket App Password", "pattern": "ATBB...", "example_masked": "ATBB..."},
    ],
    "Authentication & Generic": [
        {"type": "Hardcoded Password", "pattern": "password=...", "example_masked": 'password="..."'},
        {"type": "HTTP Auth Bearer Token", "pattern": "Bearer ...", "example_masked": "Bearer eyJhbG..."},
        {"type": "JWT (JSON Web Token)", "pattern": "eyJ...", "example_masked": "eyJhbGciOiJIUzI1NiIs..."},
        {"type": "Basic Auth Credentials", "pattern": "user:pass base64", "example_masked": "dXNlcm5hbWU6cGFz..."},
        {"type": "NPM Auth Token", "pattern": "npm_...", "example_masked": "npm_..."},
        {"type": "PyPI Token", "pattern": "pypi-...", "example_masked": "pypi-AgEIcH..."},
    ],
    "Database/Keys": [
        {"type": "Postgres Connection URI", "pattern": "postgres://user:pass@...", "example_masked": "postgres://user:***@host:5432/db"},
        {"type": "MongoDB Connection String", "pattern": "mongodb+srv://...", "example_masked": "mongodb+srv://user:***@cluster.mongodb.net/db"},
        {"type": "RSA Private Key", "pattern": "-----BEGIN RSA PRIVATE KEY-----", "example_masked": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
        {"type": "SSH Private Key", "pattern": "-----BEGIN OPENSSH PRIVATE KEY-----", "example_masked": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl..."},
    ],
}

# =============================================================================
# VARIABLE 2: Repo & Environment Context
# =============================================================================

REPO_TYPES = [
    "Prod Microservice",
    "Monolith Core",
    "Infrastructure-as-Code (Terraform/Ansible)",
    "Test/QA Suite",
    "Deprecated/Archived",
    "Internal Tooling",
    "Data Science Notebooks",
]

EXPOSURE_TYPES = [
    "Public (Open Source)",
    "Private (Internal)",
    "Internal (Partner Shared)",
]

COMMIT_AGES = [
    "Fresh (< 1 hour)",
    "Recent (1-7 days)",
    "Stale (> 6 months)",
    "Legacy (3+ years)",
]

# =============================================================================
# VARIABLE 3: Enrichment Data (Decision Drivers)
# =============================================================================

DETECTION_SOURCES = [
    "TruffleHog",
    "Gitleaks",
    "SonarQube",
    "GitHub Advanced Security",
    "Manual Bug Bounty",
]

USAGE_EVIDENCES = [
    "Active usage in CloudTrail/Logs (Last 1h)",
    "Intermittent usage (Last 7d)",
    "No usage found (90d+)",
    "Unable to verify",
]

REPO_CRITICALITIES = [
    "Critical (P0 - Customer Data)",
    "High (P1 - Business Logic)",
    "Medium (P2 - Internal)",
    "Low (P3 - Sandbox)",
]

ROTATION_STATUSES = [
    "Active/Valid",
    "Already Rotated",
    "Revoked",
    "Invalid",
]

SIMILAR_PAST_INCIDENTS = [
    "None",
    "Frequent False Positives in this file",
    "Recurring issue in this repo",
]

IMPACT_RADII = [
    "Single Service",
    "Multiple Services",
    "Cross-Team",
    "Org Wide",
]

# =============================================================================
# Sample file paths and repo names for realistic snippets
# =============================================================================

FILE_PATHS = [
    "src/config/database.py",
    "deploy/terraform/main.tf",
    "scripts/deploy.sh",
    ".env.production",
    "config/settings.yaml",
    "src/api/auth.js",
    "notebooks/data_pipeline.ipynb",
    "tests/fixtures/test_data.json",
    "infrastructure/ansible/secrets.yml",
    "backend/services/payment.py",
    "docker-compose.prod.yml",
    "k8s/secrets.yaml",
    ".github/workflows/deploy.yml",
    "src/utils/aws_client.go",
    "lib/integrations/stripe.rb",
]

REPO_NAMES = [
    "payment-service",
    "user-auth-api",
    "data-pipeline",
    "infra-terraform",
    "frontend-web",
    "backend-monolith",
    "ml-models",
    "internal-tools",
    "qa-automation",
    "legacy-billing",
    "partner-integration",
    "analytics-dashboard",
]


def get_random_vulnerability() -> Dict[str, Any]:
    """Get a random vulnerability type with its details."""
    category = random.choice(list(VULNERABILITY_CATEGORIES.keys()))
    vuln = random.choice(VULNERABILITY_CATEGORIES[category])
    return {
        "category": category,
        "type": vuln["type"],
        "masked_snippet": vuln["example_masked"],
    }


def determine_label(data: Dict[str, Any]) -> str:
    """
    Determine the appropriate label based on the data context.
    
    Logic:
    1. Mitigated: Key was valid but is now revoked/rotated.
    2. Open: Key is valid, active, and in a live repo (High Priority).
    3. Confirmed: Manual verification or logs prove immediate threat.
    4. Suppressed: Repo is archived, file is test_data.json, or key is example.
    5. False Positive: Entropy match but not a key (e.g., CSS hash, UUID).
    """
    repo_type = data["repo_details"]["type"]
    exposure = data["repo_details"]["exposure"]
    criticality = data["repo_details"]["criticality"]
    usage = data["investigation"]["usage_evidence"]
    rotation = data["investigation"]["rotation_status"]
    past_incidents = data["investigation"]["similar_past_incidents"]
    commit_age = data["detection"]["commit_age"]
    vuln_type = data["category"]
    
    # Rule 1: Already rotated/revoked -> Mitigated
    if rotation in ["Already Rotated", "Revoked"]:
        return "Mitigated"
    
    # Rule 2: Invalid credentials -> False Positive
    if rotation == "Invalid":
        return "False Positive"
    
    # Rule 3: Deprecated/Archived repos -> Suppressed
    if repo_type == "Deprecated/Archived":
        return "Suppressed"
    
    # Rule 4: Test/QA Suite with frequent false positives or example patterns -> False Positive
    if repo_type == "Test/QA Suite":
        if past_incidents == "Frequent False Positives in this file":
            return "False Positive"
        if "example" in vuln_type.lower() or "test" in vuln_type.lower():
            return "False Positive"
        # Test repos with no external exposure -> Suppressed
        if exposure == "Private (Internal)":
            return "Suppressed"
    
    # Rule 5: Active usage in last hour with public exposure -> Confirmed
    if usage == "Active usage in CloudTrail/Logs (Last 1h)" and exposure == "Public (Open Source)":
        return "Confirmed"
    
    # Rule 6: Critical repos with active usage -> Confirmed
    if criticality == "Critical (P0 - Customer Data)" and usage == "Active usage in CloudTrail/Logs (Last 1h)":
        return "Confirmed"
    
    # Rule 7: Manual Bug Bounty detection typically -> Confirmed
    if data["detection"]["source"] == "Manual Bug Bounty" and rotation == "Active/Valid":
        return "Confirmed"
    
    # Rule 8: Legacy commits with no usage in 90d+ on low priority -> Suppressed
    if commit_age == "Legacy (3+ years)" and usage == "No usage found (90d+)" and criticality == "Low (P3 - Sandbox)":
        return "Suppressed"
    
    # Rule 9: Stale internal repos with no usage -> Suppressed or Mitigated
    if commit_age == "Stale (> 6 months)" and usage == "No usage found (90d+)" and exposure == "Private (Internal)":
        return random.choice(["Suppressed", "Mitigated"])
    
    # Rule 10: Data Science Notebooks with example data -> often False Positive
    if repo_type == "Data Science Notebooks" and past_incidents == "Frequent False Positives in this file":
        return "False Positive"
    
    # Rule 11: Active/Valid in production or IaC -> Open
    if rotation == "Active/Valid":
        if repo_type in ["Prod Microservice", "Monolith Core", "Infrastructure-as-Code (Terraform/Ansible)"]:
            if usage in ["Active usage in CloudTrail/Logs (Last 1h)", "Intermittent usage (Last 7d)"]:
                return random.choice(["Open", "Confirmed"])
            return "Open"
        return "Open"
    
    # Default
    return "Open"


def generate_reasoning(data: Dict[str, Any], label: str) -> str:
    """Generate the reasoning section for the ideal LLM comment."""
    repo_type = data["repo_details"]["type"]
    exposure = data["repo_details"]["exposure"]
    criticality = data["repo_details"]["criticality"]
    usage = data["investigation"]["usage_evidence"]
    rotation = data["investigation"]["rotation_status"]
    past_incidents = data["investigation"]["similar_past_incidents"]
    impact = data["investigation"]["impact_radius"]
    
    reasons = []
    
    if label == "Mitigated":
        if rotation == "Already Rotated":
            reasons.append("Credential has already been rotated; new key is in place.")
        elif rotation == "Revoked":
            reasons.append("Credential has been revoked and is no longer valid.")
        reasons.append("No further action required. Verify rotation in key management system.")
    
    elif label == "Confirmed":
        reasons.append(f"High-confidence active threat detected.")
        if usage == "Active usage in CloudTrail/Logs (Last 1h)":
            reasons.append("Recent usage logs confirm the credential is actively being used.")
        if exposure == "Public (Open Source)":
            reasons.append("Public exposure increases risk of credential harvesting.")
        if criticality == "Critical (P0 - Customer Data)":
            reasons.append("Repository handles customer data - immediate rotation required.")
        reasons.append(f"Impact radius: {impact}. Initiate incident response protocol.")
    
    elif label == "Open":
        reasons.append("Valid credential requiring remediation.")
        if rotation == "Active/Valid":
            reasons.append("Credential is still active and has not been rotated.")
        if repo_type in ["Prod Microservice", "Monolith Core"]:
            reasons.append(f"Found in {repo_type} - prioritize based on {criticality}.")
        reasons.append("Assign to repository owner for rotation.")
    
    elif label == "Suppressed":
        if repo_type == "Deprecated/Archived":
            reasons.append("Repository is archived/deprecated with no active deployments.")
        if usage == "No usage found (90d+)":
            reasons.append("No usage detected in 90+ days.")
        if repo_type == "Test/QA Suite":
            reasons.append("Test environment with no production impact.")
        reasons.append("Risk accepted per security policy. Document and close.")
    
    elif label == "False Positive":
        if rotation == "Invalid":
            reasons.append("Credential validation failed - not a valid secret format.")
        if past_incidents == "Frequent False Positives in this file":
            reasons.append("File has history of false positive detections.")
        if repo_type == "Test/QA Suite":
            reasons.append("Test fixture or example data - not a real credential.")
        reasons.append("No remediation required. Consider adding to allowlist.")
    
    return " ".join(reasons)


def generate_ideal_comment(data: Dict[str, Any], label: str) -> str:
    """Generate the ideal LLM comment with analysis and recommendation."""
    vuln_type = data["category"]
    repo_type = data["repo_details"]["type"]
    usage = data["investigation"]["usage_evidence"]
    rotation = data["investigation"]["rotation_status"]
    reasoning = generate_reasoning(data, label)
    
    comment = f"""Automated analysis: {vuln_type} detected in {repo_type}.

Context:
- Usage: {usage}
- Status: {rotation}
- Criticality: {data["repo_details"]["criticality"]}
- Detection Source: {data["detection"]["source"]}

Recommendation: Mark as {label}.

Reasoning: {reasoning}"""
    
    return comment


def generate_ticket(ticket_num: int) -> Dict[str, Any]:
    """Generate a single ticket with random but logical features."""
    vuln = get_random_vulnerability()
    
    data = {
        "category": vuln["type"],
        "raw_secret_snippet": vuln["masked_snippet"],
        "repo_details": {
            "type": random.choice(REPO_TYPES),
            "exposure": random.choice(EXPOSURE_TYPES),
            "criticality": random.choice(REPO_CRITICALITIES),
        },
        "detection": {
            "source": random.choice(DETECTION_SOURCES),
            "commit_age": random.choice(COMMIT_AGES),
        },
        "investigation": {
            "usage_evidence": random.choice(USAGE_EVIDENCES),
            "rotation_status": random.choice(ROTATION_STATUSES),
            "impact_radius": random.choice(IMPACT_RADII),
            "similar_past_incidents": random.choice(SIMILAR_PAST_INCIDENTS),
        },
    }
    
    label = determine_label(data)
    ideal_comment = generate_ideal_comment(data, label)
    
    return {
        "ticket_id": f"SEC-{random.randint(10000, 99999)}",
        "data": data,
        "label": label,
        "ideal_llm_comment": ideal_comment,
    }


def generate_specific_ticket(ticket_num: int, overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a ticket with specific overrides to ensure label diversity."""
    vuln = get_random_vulnerability()
    
    # Build base data
    data = {
        "category": overrides.get("category", vuln["type"]),
        "raw_secret_snippet": overrides.get("raw_secret_snippet", vuln["masked_snippet"]),
        "repo_details": {
            "type": overrides.get("repo_type", random.choice(REPO_TYPES)),
            "exposure": overrides.get("exposure", random.choice(EXPOSURE_TYPES)),
            "criticality": overrides.get("criticality", random.choice(REPO_CRITICALITIES)),
        },
        "detection": {
            "source": overrides.get("detection_source", random.choice(DETECTION_SOURCES)),
            "commit_age": overrides.get("commit_age", random.choice(COMMIT_AGES)),
        },
        "investigation": {
            "usage_evidence": overrides.get("usage_evidence", random.choice(USAGE_EVIDENCES)),
            "rotation_status": overrides.get("rotation_status", random.choice(ROTATION_STATUSES)),
            "impact_radius": overrides.get("impact_radius", random.choice(IMPACT_RADII)),
            "similar_past_incidents": overrides.get("similar_past_incidents", random.choice(SIMILAR_PAST_INCIDENTS)),
        },
    }
    
    label = determine_label(data)
    ideal_comment = generate_ideal_comment(data, label)
    
    return {
        "ticket_id": f"SEC-{random.randint(10000, 99999)}",
        "data": data,
        "label": label,
        "ideal_llm_comment": ideal_comment,
    }


def generate_balanced_dataset(count: int = 100) -> list:
    """Generate a balanced dataset with diverse labels and scenarios."""
    tickets = []
    
    # Define specific cases to ensure label diversity
    specific_cases = [
        # === CONFIRMED CASES (Active, high-priority threats) ===
        {"rotation_status": "Active/Valid", "usage_evidence": "Active usage in CloudTrail/Logs (Last 1h)", 
         "exposure": "Public (Open Source)", "criticality": "Critical (P0 - Customer Data)", "repo_type": "Prod Microservice"},
        {"rotation_status": "Active/Valid", "usage_evidence": "Active usage in CloudTrail/Logs (Last 1h)", 
         "criticality": "Critical (P0 - Customer Data)", "detection_source": "Manual Bug Bounty"},
        {"rotation_status": "Active/Valid", "usage_evidence": "Active usage in CloudTrail/Logs (Last 1h)", 
         "exposure": "Public (Open Source)", "repo_type": "Infrastructure-as-Code (Terraform/Ansible)"},
        {"detection_source": "Manual Bug Bounty", "rotation_status": "Active/Valid", "exposure": "Public (Open Source)"},
        {"rotation_status": "Active/Valid", "usage_evidence": "Active usage in CloudTrail/Logs (Last 1h)", 
         "criticality": "Critical (P0 - Customer Data)", "repo_type": "Monolith Core"},
        
        # === OPEN CASES (Valid, needs remediation) ===
        {"rotation_status": "Active/Valid", "repo_type": "Prod Microservice", "usage_evidence": "Intermittent usage (Last 7d)"},
        {"rotation_status": "Active/Valid", "repo_type": "Infrastructure-as-Code (Terraform/Ansible)", "usage_evidence": "No usage found (90d+)"},
        {"rotation_status": "Active/Valid", "repo_type": "Monolith Core", "exposure": "Private (Internal)"},
        {"rotation_status": "Active/Valid", "usage_evidence": "Unable to verify", "repo_type": "Internal Tooling"},
        {"rotation_status": "Active/Valid", "repo_type": "Data Science Notebooks", "criticality": "High (P1 - Business Logic)"},
        
        # === MITIGATED CASES (Already handled) ===
        {"rotation_status": "Already Rotated", "repo_type": "Prod Microservice"},
        {"rotation_status": "Already Rotated", "repo_type": "Infrastructure-as-Code (Terraform/Ansible)"},
        {"rotation_status": "Revoked", "repo_type": "Prod Microservice"},
        {"rotation_status": "Revoked", "exposure": "Public (Open Source)"},
        {"rotation_status": "Already Rotated", "criticality": "Critical (P0 - Customer Data)"},
        
        # === SUPPRESSED CASES (Risk accepted) ===
        {"repo_type": "Deprecated/Archived", "rotation_status": "Active/Valid"},
        {"repo_type": "Deprecated/Archived", "usage_evidence": "No usage found (90d+)"},
        {"repo_type": "Test/QA Suite", "exposure": "Private (Internal)", "rotation_status": "Active/Valid"},
        {"commit_age": "Legacy (3+ years)", "usage_evidence": "No usage found (90d+)", "criticality": "Low (P3 - Sandbox)"},
        {"commit_age": "Stale (> 6 months)", "usage_evidence": "No usage found (90d+)", "exposure": "Private (Internal)"},
        
        # === FALSE POSITIVE CASES (Not real secrets) ===
        {"rotation_status": "Invalid", "repo_type": "Test/QA Suite"},
        {"rotation_status": "Invalid", "detection_source": "Gitleaks"},
        {"repo_type": "Test/QA Suite", "similar_past_incidents": "Frequent False Positives in this file"},
        {"repo_type": "Data Science Notebooks", "similar_past_incidents": "Frequent False Positives in this file"},
        {"rotation_status": "Invalid", "repo_type": "Internal Tooling"},
    ]
    
    # Generate specific cases first (25 curated examples)
    for i, case in enumerate(specific_cases):
        ticket = generate_specific_ticket(i + 1, case)
        tickets.append(ticket)
    
    # Generate remaining random tickets to reach count
    while len(tickets) < count:
        ticket = generate_ticket(len(tickets) + 1)
        tickets.append(ticket)
    
    return tickets


def main():
    """Generate and save the synthetic dataset."""
    random.seed(42)  # For reproducibility
    
    tickets = generate_balanced_dataset(500)
    
    # Write to JSONL file
    output_file = "security_tickets.jsonl"
    with open(output_file, "w") as f:
        for ticket in tickets:
            f.write(json.dumps(ticket) + "\n")
    
    # Calculate and print statistics
    label_counts = {}
    category_counts = {}
    repo_type_counts = {}
    
    for ticket in tickets:
        label = ticket["label"]
        category = ticket["data"]["category"]
        repo_type = ticket["data"]["repo_details"]["type"]
        
        label_counts[label] = label_counts.get(label, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        repo_type_counts[repo_type] = repo_type_counts.get(repo_type, 0) + 1
    
    print(f"✅ Generated {len(tickets)} tickets to {output_file}")
    print("\n📊 Label Distribution:")
    print("-" * 40)
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = count / len(tickets) * 100
        bar = "█" * int(pct / 2)
        print(f"  {label:15} {count:3} ({pct:5.1f}%) {bar}")
    
    print("\n🔐 Vulnerability Type Distribution:")
    print("-" * 40)
    for category, count in sorted(category_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {category[:35]:35} {count:3}")
    
    print("\n📁 Repository Type Distribution:")
    print("-" * 40)
    for repo_type, count in sorted(repo_type_counts.items(), key=lambda x: -x[1]):
        print(f"  {repo_type[:40]:40} {count:3}")
    
    # Show sample tickets
    print("\n" + "=" * 60)
    print("📝 SAMPLE TICKETS")
    print("=" * 60)
    
    # Show one of each label
    shown_labels = set()
    for ticket in tickets:
        if ticket["label"] not in shown_labels:
            shown_labels.add(ticket["label"])
            print(f"\n--- {ticket['ticket_id']} [{ticket['label']}] ---")
            print(json.dumps(ticket, indent=2))
        if len(shown_labels) == 5:
            break


if __name__ == "__main__":
    main()
