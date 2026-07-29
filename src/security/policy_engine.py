from core.security_constants import (

    ALLOW,

    ESCALATE,

    STRICT_MONITORING,

    BLOCK,

    STRICT_MONITORING_THRESHOLD,

    BLOCK_THRESHOLD,

    NORMAL_MONITORING,

    ELEVATED_MONITORING,

    HIGH_ALERT_MONITORING,

    CRITICAL_MONITORING,

    REQUEST_ALLOWED,

    REQUEST_ALLOWED_WITH_MONITORING,

    REQUEST_ALLOWED_UNDER_OBSERVATION,

    REQUEST_DENIED

)

# -----------------------------------------
# SECURITY POLICY ENGINE
# -----------------------------------------

def evaluate_security_policy(

    threat_classification,

    pattern_analysis

):

    # -----------------------------------------
    # EXTRACT THREAT DATA
    # -----------------------------------------

    threat_priority = threat_classification[
        "priority"
    ]

    event_count = pattern_analysis[
        "event_count"
    ]

    # -----------------------------------------
    # DEFAULT SECURITY DECISION
    # -----------------------------------------

    security_decision = {

        "decision":
        ALLOW,

        "response_action":
        REQUEST_ALLOWED,

        "monitoring_status":
        NORMAL_MONITORING,

        "reason":
        "No major security concern detected"

    }

    # -----------------------------------------
    # HIGH PRIORITY THREAT POLICY
    # -----------------------------------------

    if threat_priority == "HIGH":

        security_decision = {

            "decision":
            ESCALATE,

            "response_action":
            REQUEST_ALLOWED_WITH_MONITORING,

            "monitoring_status":
            ELEVATED_MONITORING,

            "reason":
            "High-priority threat detected"

        }

    # -----------------------------------------
    # CRITICAL PRIORITY THREAT POLICY
    # -----------------------------------------

    if threat_priority == "CRITICAL":

        security_decision = {

            "decision":
            BLOCK,

            "response_action":
            REQUEST_DENIED,

            "monitoring_status":
            CRITICAL_MONITORING,

            "reason":
            "Critical threat detected"

        }

    # -----------------------------------------
    # ESCALATION TIER 1
    # -----------------------------------------

    if event_count >= STRICT_MONITORING_THRESHOLD:

        security_decision = {

            "decision":
            STRICT_MONITORING,

            "response_action":
            REQUEST_ALLOWED_UNDER_OBSERVATION,

            "monitoring_status":
            HIGH_ALERT_MONITORING,

            "reason":
            "Repeated suspicious activity detected"

        }

    # -----------------------------------------
    # ESCALATION TIER 2
    # -----------------------------------------

    if event_count >= BLOCK_THRESHOLD:

        security_decision = {

            "decision":
            BLOCK,

            "response_action":
            REQUEST_DENIED,

            "monitoring_status":
            CRITICAL_MONITORING,

            "reason":
            "Persistent suspicious activity detected"

        }

    return security_decision