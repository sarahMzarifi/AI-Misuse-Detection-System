# -----------------------------------------
# THREAT CLASSIFIER
# -----------------------------------------

"""
This module standardizes threat classification
based on the results produced by the analysis
engine.

It converts raw analysis results into a
consistent threat classification object that
can be consumed by the policy engine,
reporting, monitoring, and logging modules.
"""

from security.threat_constants import (

    # Categories
    SAFE_REQUEST,
    PROMPT_INJECTION,
    SYSTEM_MANIPULATION,
    DATA_EXFILTRATION,
    CREDENTIAL_ATTACK,
    SOCIAL_ENGINEERING,
    MALICIOUS_CODE_REQUEST,
    SUSPICIOUS_ACTIVITY,
    UNKNOWN_THREAT,

    # Families
    NO_THREAT,
    INSTRUCTION_MANIPULATION,
    INFORMATION_DISCLOSURE,
    AUTHENTICATION_ATTACK,
    SOCIAL_ENGINEERING_ATTACK,
    MALICIOUS_CODE_GENERATION,
    ABNORMAL_BEHAVIOR,
    UNCLASSIFIED,

    # Types
    SAFE,
    BEHAVIORAL,
    SYSTEM,
    ACCESS,
    DATA,
    CODE,
    UNKNOWN,

    # Confidence
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    HIGH_CONFIDENCE,

    # Priority
    LOW_PRIORITY,
    MEDIUM_PRIORITY,
    HIGH_PRIORITY,
    CRITICAL_PRIORITY
)


# -----------------------------------------
# THREAT CLASSIFICATION
# -----------------------------------------

def classify_threat(analysis_result):

    """
    Builds a standardized threat classification
    from the analysis results.
    """

    intent_analysis = analysis_result.get(
        "intent_analysis",
        {}
    )

    intent_type = intent_analysis.get(
        "intent_type",
        ""
    )

    severity = intent_analysis.get(
        "severity",
        "LOW"
    )

    # -----------------------------------------
    # SAFE REQUEST
    # -----------------------------------------

    if severity == "LOW":

        return {

            "category": SAFE_REQUEST,

            "family": NO_THREAT,

            "type": SAFE,

            "confidence": HIGH_CONFIDENCE,

            "priority": LOW_PRIORITY

        }

    # -----------------------------------------
    # PROMPT INJECTION
    # -----------------------------------------

    if intent_type == "Prompt Injection":

        return {

            "category": PROMPT_INJECTION,

            "family": INSTRUCTION_MANIPULATION,

            "type": SYSTEM,

            "confidence": HIGH_CONFIDENCE,

            "priority": CRITICAL_PRIORITY

        }

    # -----------------------------------------
    # SYSTEM MANIPULATION
    # -----------------------------------------

    if intent_type == "System Manipulation":

        return {

            "category": SYSTEM_MANIPULATION,

            "family": INSTRUCTION_MANIPULATION,

            "type": SYSTEM,

            "confidence": HIGH_CONFIDENCE,

            "priority": HIGH_PRIORITY

        }

    # -----------------------------------------
    # DATA EXFILTRATION
    # -----------------------------------------

    if intent_type == "Sensitive Data Exposure":

        return {

            "category": DATA_EXFILTRATION,

            "family": INFORMATION_DISCLOSURE,

            "type": DATA,

            "confidence": HIGH_CONFIDENCE,

            "priority": CRITICAL_PRIORITY

        }

    # -----------------------------------------
    # CREDENTIAL ATTACK
    # -----------------------------------------

    if intent_type == "Authentication Bypass":

        return {

            "category": CREDENTIAL_ATTACK,

            "family": AUTHENTICATION_ATTACK,

            "type": ACCESS,

            "confidence": HIGH_CONFIDENCE,

            "priority": CRITICAL_PRIORITY

        }

    # -----------------------------------------
    # SOCIAL ENGINEERING
    # -----------------------------------------

    if intent_type == "Social Engineering":

        return {

            "category": SOCIAL_ENGINEERING,

            "family": SOCIAL_ENGINEERING_ATTACK,

            "type": BEHAVIORAL,

            "confidence": MEDIUM_CONFIDENCE,

            "priority": HIGH_PRIORITY

        }

    # -----------------------------------------
    # MALICIOUS CODE REQUEST
    # -----------------------------------------

    if intent_type == "Malicious Code Generation":

        return {

            "category": MALICIOUS_CODE_REQUEST,

            "family": MALICIOUS_CODE_GENERATION,

            "type": CODE,

            "confidence": HIGH_CONFIDENCE,

            "priority": HIGH_PRIORITY

        }

    # -----------------------------------------
    # GENERIC SUSPICIOUS ACTIVITY
    # -----------------------------------------

    if severity == "MEDIUM":

        return {

            "category": SUSPICIOUS_ACTIVITY,

            "family": ABNORMAL_BEHAVIOR,

            "type": BEHAVIORAL,

            "confidence": MEDIUM_CONFIDENCE,

            "priority": MEDIUM_PRIORITY

        }

    if severity == "HIGH":

        return {

            "category": SUSPICIOUS_ACTIVITY,

            "family": ABNORMAL_BEHAVIOR,

            "type": BEHAVIORAL,

            "confidence": HIGH_CONFIDENCE,

            "priority": HIGH_PRIORITY

        }

    # -----------------------------------------
    # UNKNOWN THREAT
    # -----------------------------------------

    return {

        "category": UNKNOWN_THREAT,

        "family": UNCLASSIFIED,

        "type": UNKNOWN,

        "confidence": LOW_CONFIDENCE,

        "priority": LOW_PRIORITY

    }