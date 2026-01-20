#!/usr/bin/env python3
"""
Fix security_tickets.jsonl by correcting labels and regenerating ideal_llm_comments
based on the SecTriageBot decision logic.
"""

import json
from pathlib import Path


def apply_decision_logic(data: dict) -> str:
    """Apply SecTriageBot decision logic to determine correct label."""
    rotation_status = data["investigation"]["rotation_status"]
    repo_type = data["repo_details"]["type"]
    usage_evidence = data["investigation"]["usage_evidence"]
    criticality = data["repo_details"]["criticality"]
    exposure = data["repo_details"]["exposure"]
    past_incidents = data["investigation"]["similar_past_incidents"]
    
    # Priority 1: MITIGATED - Revoked or Already Rotated
    if rotation_status in ["Revoked", "Already Rotated"]:
        return "Mitigated"
    
    # Priority 2: FALSE POSITIVE - Invalid credential
    if rotation_status == "Invalid":
        return "False Positive"
    
    # Priority 3: SUPPRESSED - Archived/Deprecated repos only
    if "Deprecated" in repo_type or "Archived" in repo_type:
        return "Suppressed"
    
    # Check for active usage
    is_active_usage = "Active usage" in usage_evidence
    is_high_criticality = "P0" in criticality or "P1" in criticality
    is_public = "Public" in exposure
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

    return "Open"


def generate_comment(data: dict, label: str) -> str:
    """Generate the ideal_llm_comment based on data and label."""
    category = data["category"]
    repo_type = data["repo_details"]["type"]
    usage = data["investigation"]["usage_evidence"]
    status = data["investigation"]["rotation_status"]
    criticality = data["repo_details"]["criticality"]
    detection = data["detection"]["source"]
    exposure = data["repo_details"]["exposure"]
    impact = data["investigation"]["impact_radius"]
    past_incidents = data["investigation"]["similar_past_incidents"]
    
    # Build context section
    headline = f"Automated analysis: {category} detected in {repo_type}."
    context = f"""
Context:
- Usage: {usage}
- Status: {status}
- Criticality: {criticality}
- Detection Source: {detection}"""
    
    recommendation = f"\nRecommendation: Mark as {label}."
    
    # Build reasoning based on label
    if label == "Mitigated":
        if status == "Revoked":
            reasoning = "\nReasoning: Credential has been revoked and is no longer valid. No further action required. Verify rotation in key management system."
        else:
            reasoning = "\nReasoning: Credential has already been rotated; new key is in place. No further action required. Verify rotation in key management system."
    
    elif label == "False Positive":
        reasons = []
        if status == "Invalid":
            reasons.append("Credential validation failed - not a valid secret format.")
        if past_incidents == "Frequent False Positives in this file":
            reasons.append("File has history of false positive detections.")
        if "Test" in repo_type or "QA" in repo_type:
            reasons.append("Test fixture or example data - not a real credential.")
        reasons.append("No remediation required. Consider adding to allowlist.")
        reasoning = "\nReasoning: " + " ".join(reasons)
    
    elif label == "Suppressed":
        reasons = ["Repository is archived/deprecated with no active deployments."]
        if "No usage found" in usage:
            reasons.append("No usage detected in 90+ days.")
        reasons.append("Risk accepted per security policy. Document and close.")
        reasoning = "\nReasoning: " + " ".join(reasons)
    
    elif label == "Confirmed":
        reasons = ["High-confidence active threat detected."]
        if "Active usage" in usage:
            reasons.append("Recent usage logs confirm the credential is actively being used.")
        if "Public" in exposure:
            reasons.append("Public exposure increases risk of credential harvesting.")
        if "P0" in criticality:
            reasons.append("Repository handles customer data - immediate rotation required.")
        reasons.append(f"Impact radius: {impact}. Initiate incident response protocol.")
        reasoning = "\nReasoning: " + " ".join(reasons)
    
    else:  # Open
        reasons = ["Valid credential requiring remediation.", "Credential is still active and has not been rotated."]
        if "Prod" in repo_type or "Monolith" in repo_type:
            reasons.append(f"Found in {repo_type} - prioritize based on {criticality}.")
        reasons.append("Assign to repository owner for rotation.")
        reasoning = "\nReasoning: " + " ".join(reasons)
    
    return headline + context + recommendation + reasoning


def fix_dataset(input_path: str, output_path: str):
    """Fix all tickets and write corrected dataset."""
    fixed_count = 0
    total = 0
    
    with open(input_path, "r") as f_in, open(output_path, "w") as f_out:
        for line in f_in:
            if not line.strip():
                continue
            
            ticket = json.loads(line)
            total += 1
            
            correct_label = apply_decision_logic(ticket["data"])
            
            if ticket["label"] != correct_label:
                fixed_count += 1
                print(f"Fixed {ticket['ticket_id']}: {ticket['label']} -> {correct_label}")
            
            # Update ticket with correct label and regenerated comment
            ticket["label"] = correct_label
            ticket["ideal_llm_comment"] = generate_comment(ticket["data"], correct_label)
            
            f_out.write(json.dumps(ticket) + "\n")
    
    print(f"\n{'='*60}")
    print(f"Total tickets: {total}")
    print(f"Fixed: {fixed_count}")
    print(f"Output written to: {output_path}")
    return fixed_count


if __name__ == "__main__":
    input_file = Path(__file__).parent / "security_tickets.jsonl"
    output_file = Path(__file__).parent / "security_tickets_fixed.jsonl"
    
    fixed = fix_dataset(str(input_file), str(output_file))
    
    if fixed > 0:
        print(f"\n✅ Fixed {fixed} tickets. Review the output file and replace original when ready.")
        print(f"   To replace: mv security_tickets_fixed.jsonl security_tickets.jsonl")
