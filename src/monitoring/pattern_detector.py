# -----------------------------------------
# PATTERN DETECTION CONFIGURATION
# -----------------------------------------

HIGH_RISK_THRESHOLD = 3


# -----------------------------------------
# DETECT REPEATED HIGH-RISK ACTIVITY
# -----------------------------------------

def detect_repeated_high_risk_activity(
    threat_history
):

    high_risk_events = []

    # -----------------------------------------
    # FILTER HIGH-RISK EVENTS
    # -----------------------------------------

    for event in threat_history:

        if event["risk_level"] == "HIGH":

            high_risk_events.append(event)

    # -----------------------------------------
    # DETECT SUSPICIOUS PATTERN
    # -----------------------------------------

    if len(high_risk_events) >= HIGH_RISK_THRESHOLD:

        return {

            "pattern_detected": True,

            "pattern_type":
            "REPEATED_HIGH_RISK_ACTIVITY",

            "event_count":
            len(high_risk_events),

            "message": (

                "Repeated HIGH-risk activity "
                "detected in threat history"

            )
        }

    # -----------------------------------------
    # NO PATTERN DETECTED
    # -----------------------------------------

    return {

        "pattern_detected": False,

        "pattern_type": None,

        "event_count":
        len(high_risk_events),

        "message":
        "No suspicious behavioral pattern detected"

    }