from datetime import datetime

# -----------------------------------------
# CREATE STRUCTURED SECURITY EVENT
# -----------------------------------------

def create_security_event(

    request_id,

    risk_level,

    threat_classification

):

    # -----------------------------------------
    # EXTRACT THREAT INFORMATION
    # -----------------------------------------

    threat_category = threat_classification[
        "category"
    ]

    threat_family = threat_classification[
        "family"
    ]

    threat_type = threat_classification[
        "type"
    ]

    threat_confidence = threat_classification[
        "confidence"
    ]

    threat_priority = threat_classification[
        "priority"
    ]

    # -----------------------------------------
    # DETERMINE EVENT SEVERITY
    # -----------------------------------------

    event_severity = "INFO"

    if risk_level == "HIGH":

        event_severity = "WARNING"

    if threat_priority == "HIGH":

        event_severity = "CRITICAL"

    if threat_priority == "CRITICAL":

        event_severity = "CRITICAL"

    # -----------------------------------------
    # STRUCTURED EVENT OBJECT
    # -----------------------------------------

    security_event = {

        "event_type":
        "HIGH_RISK_PROMPT",

        "event_severity":
        event_severity,

        "request_id":
        request_id,

        "timestamp":
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "risk_level":
        risk_level,

        "threat_category":
        threat_category,

        "threat_family":
        threat_family,

        "threat_type":
        threat_type,

        "threat_confidence":
        threat_confidence,

        "threat_priority":
        threat_priority

    }

    return security_event