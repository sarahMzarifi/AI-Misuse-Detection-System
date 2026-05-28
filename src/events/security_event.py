from datetime import datetime

# -----------------------------------------
# CREATE STRUCTURED SECURITY EVENT
# -----------------------------------------

def create_security_event(

    request_id,

    risk_level,

    intent_type,

    severity

):

    # -----------------------------------------
    # DETERMINE EVENT SEVERITY
    # -----------------------------------------

    event_severity = "INFO"

    if risk_level == "HIGH":

        event_severity = "WARNING"

    if severity == "HIGH":

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

        "intent_type":
        intent_type,

        "severity":
        severity

    }

    return security_event