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
    # STRUCTURED EVENT OBJECT
    # -----------------------------------------

    security_event = {

        "event_type":
        "HIGH_RISK_PROMPT",

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