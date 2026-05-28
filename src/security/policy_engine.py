# -----------------------------------------
# SECURITY POLICY ENGINE
# -----------------------------------------

def evaluate_security_policy(

    analysis_result,

    pattern_analysis

):

    # -----------------------------------------
    # EXTRACT ANALYSIS DATA
    # -----------------------------------------

    risk_level = analysis_result[
        "risk_analysis"
    ]["risk_level"]

    event_count = pattern_analysis[
        "event_count"
    ]

    # -----------------------------------------
    # DEFAULT SECURITY DECISION
    # -----------------------------------------

    security_decision = {

        "decision":
        "ALLOW",

        "response_action":
        "REQUEST_ALLOWED",

        "monitoring_status":
        "NORMAL_MONITORING",

        "reason":
        "No major security concern detected"

    }

    # -----------------------------------------
    # HIGH-RISK POLICY
    # -----------------------------------------

    if risk_level == "HIGH":

        security_decision = {

            "decision":
            "ESCALATE",

            "response_action":
            "REQUEST_ALLOWED_WITH_MONITORING",

            "monitoring_status":
            "ELEVATED_MONITORING",

            "reason":
            "High-risk activity detected"

        }

    # -----------------------------------------
    # ESCALATION TIER 1
    # -----------------------------------------

    if event_count >= 3:

        security_decision = {

            "decision":
            "STRICT_MONITORING",

            "response_action":
            "REQUEST_ALLOWED_UNDER_OBSERVATION",

            "monitoring_status":
            "HIGH_ALERT_MONITORING",

            "reason":
            "Repeated suspicious activity detected"

        }

    # -----------------------------------------
    # ESCALATION TIER 2
    # -----------------------------------------

    if event_count >= 5:

        security_decision = {

            "decision":
            "BLOCK",

            "response_action":
            "REQUEST_DENIED",

            "monitoring_status":
            "CRITICAL_MONITORING",

            "reason":
            "Persistent suspicious activity detected"

        }

    return security_decision