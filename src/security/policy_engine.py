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

    pattern_analysis,

    confidence_analysis

):

    # -----------------------------------------
    # EXTRACT THREAT DATA
    # -----------------------------------------

    threat_priority = threat_classification.get(
        "priority",
        "LOW"
    )

    event_count = pattern_analysis.get(
        "event_count",
        0
    )

    # -----------------------------------------
    # EXTRACT CONFIDENCE DATA
    # -----------------------------------------

    confidence_score = confidence_analysis.get(
        "score",
        0
    )

    confidence_level = confidence_analysis.get(
        "level",
        "LOW"
    )

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
    # CRITICAL PRIORITY THREAT
    # -----------------------------------------
    #
    # Critical threats are blocked regardless
    # of confidence level.
    #
    # Confidence must not weaken a critical
    # security decision.
    # -----------------------------------------

    if threat_priority == "CRITICAL":

        return {

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
    # PERSISTENT SUSPICIOUS ACTIVITY
    # -----------------------------------------
    #
    # Repeated suspicious activity reaching
    # the block threshold results in blocking.
    #
    # This applies even if the current threat
    # priority is not CRITICAL.
    # -----------------------------------------

    if event_count >= BLOCK_THRESHOLD:

        return {

            "decision":
            BLOCK,

            "response_action":
            REQUEST_DENIED,

            "monitoring_status":
            CRITICAL_MONITORING,

            "reason":
            "Persistent suspicious activity detected"

        }

    # -----------------------------------------
    # REPEATED SUSPICIOUS ACTIVITY
    # -----------------------------------------
    #
    # Repeated activity reaching the strict
    # monitoring threshold increases the
    # response level.
    #
    # This happens before the normal HIGH
    # priority policy.
    # -----------------------------------------

    if event_count >= STRICT_MONITORING_THRESHOLD:

        return {

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
    # HIGH PRIORITY + HIGH CONFIDENCE
    # -----------------------------------------
    #
    # Strong evidence supports an elevated
    # security response.
    # -----------------------------------------

    if (
        threat_priority == "HIGH"
        and confidence_level == "HIGH"
    ):

        return {

            "decision":
            ESCALATE,

            "response_action":
            REQUEST_ALLOWED_WITH_MONITORING,

            "monitoring_status":
            ELEVATED_MONITORING,

            "reason":
            (
                "High-priority threat detected "
                f"with HIGH confidence "
                f"({confidence_score})"
            )

        }

    # -----------------------------------------
    # HIGH PRIORITY + LOWER CONFIDENCE
    # -----------------------------------------
    #
    # The threat is important, but confidence
    # is not strong enough for the normal
    # HIGH-priority escalation response.
    #
    # The request remains under strict
    # monitoring rather than being treated
    # as a normal request.
    # -----------------------------------------

    if (
        threat_priority == "HIGH"
        and confidence_level in (
            "MEDIUM",
            "LOW"
        )
    ):

        return {

            "decision":
            STRICT_MONITORING,

            "response_action":
            REQUEST_ALLOWED_UNDER_OBSERVATION,

            "monitoring_status":
            HIGH_ALERT_MONITORING,

            "reason":
            (
                "High-priority threat detected "
                f"with {confidence_level} confidence "
                f"({confidence_score})"
            )

        }

    # -----------------------------------------
    # RETURN DEFAULT DECISION
    # -----------------------------------------

    return security_decision