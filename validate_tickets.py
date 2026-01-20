#!/usr/bin/env python3
"""
Validate security_tickets.jsonl against SecTriageBot decision logic.

Decision Logic:
- MITIGATED: rotation_status is "Revoked" or "Already Rotated"
- FALSE POSITIVE: rotation_status is "Invalid", or file has known test fixtures, 
                  or similar_past_incidents indicates frequent false alarms
- SUPPRESSED: repo_details.type is "Archived" or "Legacy" (Deprecated/Archived)
- OPEN: secret is "Active/Valid" in a "Prod" or "Public" repo
- CONFIRMED: active usage in logs OR high-criticality leak
"""

import json
from collections import defaultdict
from pathlib import Path


def apply_decision_logic(data: dict) -> str:
    """Apply SecTriageBot decision logic to determine expected label."""
    rotation_status = data["investigation"]["rotation_status"]
    repo_type = data["repo_details"]["type"]
    usage_evidence = data["investigation"]["usage_evidence"]
    criticality = data["repo_details"]["criticality"]
    exposure = data["repo_details"]["exposure"]
    past_incidents = data["investigation"]["similar_past_incidents"]
    
    # Priority 1: MITIGATED - Check rotation status first
    if rotation_status in ["Revoked", "Already Rotated"]:
        return "Mitigated"
    
    # Priority 2: FALSE POSITIVE - Invalid credential or test fixture patterns
    if rotation_status == "Invalid":
        return "False Positive"
    
    # Priority 3: SUPPRESSED - Archived/Legacy repos
    if "Deprecated" in repo_type or "Archived" in repo_type:
        return "Suppressed"
    
    # Check for active usage
    is_active_usage = "Active usage" in usage_evidence
    is_high_criticality = "P0" in criticality or "P1" in criticality
    is_public = "Public" in exposure
    is_prod_or_monolith = "Prod" in repo_type or "Monolith" in repo_type
    is_test_qa = repo_type == "Test/QA Suite"
    
    # Priority 4: Test/QA with FP history AND no active usage -> False Positive
    if is_test_qa and past_incidents == "Frequent False Positives in this file" and not is_active_usage:
        return "False Positive"
    
    # Priority 5: CONFIRMED - Active usage always confirms the threat
    if rotation_status == "Active/Valid" and is_active_usage:
        return "Confirmed"
    
    # Priority 6: CONFIRMED - High criticality with public exposure (even without active usage)
    if rotation_status == "Active/Valid" and is_high_criticality and is_public:
        return "Confirmed"
    
    # Priority 7: OPEN - Active/Valid credential needing rotation
    if rotation_status == "Active/Valid":
        return "Open"
    
    # Default fallback
    return "Open"


def validate_dataset(filepath: str) -> dict:
    """Validate all tickets in the JSONL file."""
    results = {
        "total": 0,
        "matches": 0,
        "mismatches": [],
        "by_label": defaultdict(lambda: {"correct": 0, "incorrect": 0}),
    }
    
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            ticket = json.loads(line)
            results["total"] += 1
            
            expected_label = apply_decision_logic(ticket["data"])
            actual_label = ticket["label"]
            
            if expected_label.lower() == actual_label.lower():
                results["matches"] += 1
                results["by_label"][actual_label]["correct"] += 1
            else:
                results["mismatches"].append({
                    "line": line_num,
                    "ticket_id": ticket["ticket_id"],
                    "expected": expected_label,
                    "actual": actual_label,
                    "rotation_status": ticket["data"]["investigation"]["rotation_status"],
                    "repo_type": ticket["data"]["repo_details"]["type"],
                    "usage": ticket["data"]["investigation"]["usage_evidence"],
                    "criticality": ticket["data"]["repo_details"]["criticality"],
                    "past_incidents": ticket["data"]["investigation"]["similar_past_incidents"],
                })
                results["by_label"][actual_label]["incorrect"] += 1
    
    return results


def print_report(results: dict):
    """Print a formatted validation report."""
    print("=" * 70)
    print("SECURITY TICKET DATASET VALIDATION REPORT")
    print("=" * 70)
    
    accuracy = (results["matches"] / results["total"]) * 100 if results["total"] > 0 else 0
    print(f"\nTotal Tickets: {results['total']}")
    print(f"Matches: {results['matches']}")
    print(f"Mismatches: {len(results['mismatches'])}")
    print(f"Accuracy: {accuracy:.2f}%")
    
    print("\n" + "-" * 70)
    print("BREAKDOWN BY LABEL:")
    print("-" * 70)
    for label, counts in sorted(results["by_label"].items()):
        total = counts["correct"] + counts["incorrect"]
        pct = (counts["correct"] / total) * 100 if total > 0 else 0
        print(f"  {label:15} | Correct: {counts['correct']:3} | Incorrect: {counts['incorrect']:3} | Accuracy: {pct:.1f}%")
    
    if results["mismatches"]:
        print("\n" + "-" * 70)
        print(f"DISCREPANCIES (showing first 20 of {len(results['mismatches'])}):")
        print("-" * 70)
        
        for m in results["mismatches"][:20]:
            print(f"\n  Ticket: {m['ticket_id']} (Line {m['line']})")
            print(f"    Expected: {m['expected']} | Actual: {m['actual']}")
            print(f"    Rotation: {m['rotation_status']} | Repo: {m['repo_type']}")
            print(f"    Usage: {m['usage']}")
            print(f"    Criticality: {m['criticality']}")
            print(f"    Past Incidents: {m['past_incidents']}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    filepath = Path(__file__).parent / "security_tickets.jsonl"
    results = validate_dataset(filepath)
    print_report(results)
    
    # Save detailed mismatches to file
    if results["mismatches"]:
        output_path = Path(__file__).parent / "validation_mismatches.json"
        with open(output_path, "w") as f:
            json.dump(results["mismatches"], f, indent=2)
        print(f"\nFull mismatch details saved to: {output_path}")
