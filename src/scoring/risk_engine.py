# CENTRALIZED RISK WEIGHT CONFIGURATION

INTENT_SEVERITY_SCORES = {
    "LOW": 10,
    "MEDIUM": 40,
    "HIGH": 80
}


DETECTION_TYPE_SCORES = {
    "PASSWORD DETECTED": 40,
    "API KEY DETECTED": 50,
    "EMAIL DETECTED": 10
}


# FINAL RISK CALCULATION ENGINE
def calculate_final_risk(
    detection_results,
    intent_analysis
):

    # INITIALIZE SCORING VARIABLES

    total_score = 0
    reasons = []

    # PROCESS DETECTION RESULTS

    for detection in detection_results:
        detection_type = detection[0]
        if detection_type in DETECTION_TYPE_SCORES:
            total_score += (
                DETECTION_TYPE_SCORES[detection_type]
            )
            reasons.append(
                f"{detection_type} contributed to risk score"
            )

    # PROCESS INTENT ANALYSIS

    intent_severity = intent_analysis[
        "severity"
    ]
    if intent_severity in INTENT_SEVERITY_SCORES:
        total_score += (
            INTENT_SEVERITY_SCORES[
                intent_severity
            ]
        )

        reasons.append(
            f"Intent severity "
            f"'{intent_severity}' "
            f"contributed to risk score"
        )

    # DETERMINE FINAL RISK LEVEL

    if total_score >= 80:
        risk_level = "HIGH"

    elif total_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # RETURN FINAL CENTRALIZED RISK RESULT

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "reasons": reasons
    }