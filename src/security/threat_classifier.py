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

The classifier uses both intent severity and
intent confidence when determining the final
threat classification.
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

    Classification considers:

    1. Intent type
    2. Intent severity
    3. Intent confidence
    """

    # -----------------------------------------
    # EXTRACT INTENT ANALYSIS
    # -----------------------------------------

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
    # EXTRACT CONFIDENCE
    # -----------------------------------------

    confidence_data = intent_analysis.get(
        "confidence",
        {}
    )

    confidence_level = confidence_data.get(
        "level",
        LOW_CONFIDENCE
    )


    # -----------------------------------------
    # SAFE REQUEST
    # -----------------------------------------

    if severity == "LOW":

        return {

            "category":
            SAFE_REQUEST,

            "family":
            NO_THREAT,

            "type":
            SAFE,

            "confidence":
            HIGH_CONFIDENCE,

            "priority":
            LOW_PRIORITY

        }


    # -----------------------------------------
    # PROMPT INJECTION
    # -----------------------------------------

    if intent_type == "PROMPT_INJECTION":

        return {

            "category":
            PROMPT_INJECTION,

            "family":
            INSTRUCTION_MANIPULATION,

            "type":
            SYSTEM,

            "confidence":
            confidence_level,

            "priority":
            CRITICAL_PRIORITY

        }


    # -----------------------------------------
    # SYSTEM MANIPULATION
    # -----------------------------------------

    if intent_type == "SYSTEM_MANIPULATION":

        if confidence_level == LOW_CONFIDENCE:

            priority = MEDIUM_PRIORITY

        elif confidence_level == MEDIUM_CONFIDENCE:

            priority = HIGH_PRIORITY

        else:

            priority = HIGH_PRIORITY

        return {

            "category":
            SYSTEM_MANIPULATION,

            "family":
            INSTRUCTION_MANIPULATION,

            "type":
            SYSTEM,

            "confidence":
            confidence_level,

            "priority":
            priority

        }


    # -----------------------------------------
    # DATA EXPOSURE / EXFILTRATION
    # -----------------------------------------

    if intent_type == "DATA_EXPOSURE":

        # -------------------------------------
        # LOW CONFIDENCE
        # -------------------------------------

        if confidence_level == LOW_CONFIDENCE:

            priority = MEDIUM_PRIORITY

        # -------------------------------------
        # MEDIUM CONFIDENCE
        # -------------------------------------

        elif confidence_level == MEDIUM_CONFIDENCE:

            priority = MEDIUM_PRIORITY

        # -------------------------------------
        # HIGH CONFIDENCE
        # -------------------------------------

        else:

            priority = HIGH_PRIORITY

        return {

            "category":
            DATA_EXFILTRATION,

            "family":
            INFORMATION_DISCLOSURE,

            "type":
            DATA,

            "confidence":
            confidence_level,

            "priority":
            priority

        }


    # -----------------------------------------
    # AUTHENTICATION BYPASS
    # -----------------------------------------

    if intent_type == "AUTH_BYPASS_ATTEMPT":

        return {

            "category":
            CREDENTIAL_ATTACK,

            "family":
            AUTHENTICATION_ATTACK,

            "type":
            ACCESS,

            "confidence":
            confidence_level,

            "priority":
            CRITICAL_PRIORITY

        }


    # -----------------------------------------
    # CREDENTIAL THEFT
    # -----------------------------------------

    if intent_type == "CREDENTIAL_THEFT":

        return {

            "category":
            CREDENTIAL_ATTACK,

            "family":
            AUTHENTICATION_ATTACK,

            "type":
            ACCESS,

            "confidence":
            confidence_level,

            "priority":
            CRITICAL_PRIORITY

        }


    # -----------------------------------------
    # SOCIAL ENGINEERING
    # -----------------------------------------

    if intent_type == "SOCIAL_ENGINEERING":

        if confidence_level == LOW_CONFIDENCE:

            priority = MEDIUM_PRIORITY

        else:

            priority = HIGH_PRIORITY

        return {

            "category":
            SOCIAL_ENGINEERING,

            "family":
            SOCIAL_ENGINEERING_ATTACK,

            "type":
            BEHAVIORAL,

            "confidence":
            confidence_level,

            "priority":
            priority

        }


    # -----------------------------------------
    # MALICIOUS CODE REQUEST
    # -----------------------------------------

    if intent_type == "MALICIOUS_CODE_REQUEST":

        return {

            "category":
            MALICIOUS_CODE_REQUEST,

            "family":
            MALICIOUS_CODE_GENERATION,

            "type":
            CODE,

            "confidence":
            confidence_level,

            "priority":
            HIGH_PRIORITY

        }


    # -----------------------------------------
    # GENERIC MEDIUM-RISK ACTIVITY
    # -----------------------------------------

    if severity == "MEDIUM":

        return {

            "category":
            SUSPICIOUS_ACTIVITY,

            "family":
            ABNORMAL_BEHAVIOR,

            "type":
            BEHAVIORAL,

            "confidence":
            confidence_level,

            "priority":
            MEDIUM_PRIORITY

        }


    # -----------------------------------------
    # GENERIC HIGH-RISK ACTIVITY
    # -----------------------------------------

    if severity == "HIGH":

        return {

            "category":
            SUSPICIOUS_ACTIVITY,

            "family":
            ABNORMAL_BEHAVIOR,

            "type":
            BEHAVIORAL,

            "confidence":
            confidence_level,

            "priority":
            HIGH_PRIORITY

        }


    # -----------------------------------------
    # UNKNOWN THREAT
    # -----------------------------------------

    return {

        "category":
        UNKNOWN_THREAT,

        "family":
        UNCLASSIFIED,

        "type":
        UNKNOWN,

        "confidence":
        LOW_CONFIDENCE,

        "priority":
        LOW_PRIORITY

    }