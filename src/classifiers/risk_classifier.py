def classify_risk(findings, prompt):

    score = 0
    reasons = []

    prompt_lower = prompt.lower()

    # Sensitive findings score
    for item in findings:

        finding_type = item[0]

        if "API KEY" in finding_type:
            score += 50
            reasons.append("API key exposure detected")

        elif "PASSWORD" in finding_type:
            score += 40
            reasons.append("Password exposure detected")

        elif "EMAIL" in finding_type:
            score += 10
            reasons.append("Email detected")

    # Context keywords
    risky_keywords = [
        "database",
        "confidential",
        "internal",
        "credential",
        "server",
        "private"
    ]

    for keyword in risky_keywords:

        if keyword in prompt_lower:
            score += 10
            reasons.append(f"Sensitive keyword detected: {keyword}")

    # Risk level classification
    if score >= 70:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }