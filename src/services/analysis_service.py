from detectors.sensitive_detector import detect_sensitive_data
from classifiers.risk_classifier import classify_risk
from analyzers.intent_analyzer import analyze_intent


def analyze_prompt(prompt):

    # DETECTION STAGE

    detection_results = detect_sensitive_data(prompt)

    # RISK CLASSIFICATION STAGE

    risk_analysis = classify_risk(
        detection_results,
        prompt
    )

    # INTENT ANALYSIS STAGE

    intent_analysis = analyze_intent(prompt)

    # UNIFIED STRUCTURED ANALYSIS OBJECT

    complete_analysis = {

        "prompt": prompt,

        "detection_results": detection_results,

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

            "reasons":
            intent_analysis["reasons"]
        }
    }

    # RETURN FINAL STRUCTURED OBJECT

    return complete_analysis