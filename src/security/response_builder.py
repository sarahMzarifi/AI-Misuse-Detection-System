# -----------------------------------------
# SECURITY RESPONSE BUILDER
# -----------------------------------------

"""
This module is responsible for constructing
standardized API responses for the security backend.

It separates response formatting from business logic,
allowing API endpoints to focus only on request
processing and orchestration.
"""


# -----------------------------------------
# SUCCESS RESPONSE
# -----------------------------------------

def build_success_response(

    request_id,

    timestamp,

    analysis_result,

    threat_classification,

    pattern_analysis,

    security_decision

):

    return {

        "status": "success",

        "request_id": request_id,

        "timestamp": timestamp,

        "analysis_result": analysis_result,

        "threat_classification": threat_classification,

        "pattern_analysis": pattern_analysis,

        "security_decision": security_decision

    }


# -----------------------------------------
# BLOCKED RESPONSE
# -----------------------------------------

def build_blocked_response(

    request_id,

    timestamp,

    analysis_result,

    threat_classification,

    pattern_analysis,

    security_decision

):

    return {

        "status": "blocked",

        "request_id": request_id,

        "timestamp": timestamp,

        "message": "Request blocked by security policy.",

        "analysis_result": analysis_result,

        "threat_classification": threat_classification,

        "pattern_analysis": pattern_analysis,

        "security_decision": security_decision

    }


# -----------------------------------------
# ERROR RESPONSE
# -----------------------------------------

def build_error_response(

    request_id,

    timestamp,

    message,

    details

):

    return {

        "status": "error",

        "request_id": request_id,

        "timestamp": timestamp,

        "message": message,

        "details": details

    }