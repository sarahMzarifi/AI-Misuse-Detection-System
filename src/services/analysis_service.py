from detectors.sensitive_detector import (
    detect_sensitive_data
)

from analyzers.intent_analyzer import (
    analyze_intent
)

from scoring.risk_engine import (
    calculate_final_risk
)


def analyze_prompt(prompt):

    # -----------------------------------------
    # DETECTION STAGE
    # -----------------------------------------

    detection_results = detect_sensitive_data(
        prompt
    )

    # -----------------------------------------
    # INTENT ANALYSIS STAGE
    # -----------------------------------------

    intent_analysis = analyze_intent(
        prompt
    )

    # -----------------------------------------
    # CENTRALIZED RISK ENGINE
    # -----------------------------------------

    risk_analysis = calculate_final_risk(

        detection_results,

        intent_analysis

    )

    # -----------------------------------------
    # UNIFIED STRUCTURED ANALYSIS OBJECT
    # -----------------------------------------

    complete_analysis = {

        "prompt": prompt,

        "detection_results":
        detection_results,

        "risk_analysis": {

            "risk_level":
            risk_analysis["risk_level"],

            "risk_score":
            risk_analysis["risk_score"],

            "reasons":
            risk_analysis["reasons"]

        },

        "intent_analysis": {

            "intent_type":
            intent_analysis["intent_type"],

            "severity":
            intent_analysis["severity"],

            "confidence":
            intent_analysis["confidence"],

            "reasons":
            intent_analysis["reasons"]

        }

    }

    # -----------------------------------------
    # RETURN FINAL STRUCTURED OBJECT
    # -----------------------------------------

    return complete_analysis