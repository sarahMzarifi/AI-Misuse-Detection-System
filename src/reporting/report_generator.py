def generate_report(
    analysis_result,
    threat_classification,
    request_id=None,
    prompt_number=None
):

    # -----------------------------------------
    # EXTRACT ANALYSIS COMPONENTS
    # -----------------------------------------

    prompt = analysis_result["prompt"]

    detection_results = analysis_result[
        "detection_results"
    ]

    risk_analysis = analysis_result[
        "risk_analysis"
    ]

    intent_analysis = analysis_result[
        "intent_analysis"
    ]

    # -----------------------------------------
    # EXTRACT THREAT CLASSIFICATION
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
    # REPORT HEADER
    # -----------------------------------------

    report = f"""

================================================
FORENSIC PROMPT ANALYSIS REPORT
================================================

PROMPT NUMBER:
{prompt_number}

REQUEST ID:
{request_id}

PROMPT:
{prompt}

================================================
DETECTION RESULTS
================================================
"""

    # -----------------------------------------
    # DETECTION RESULTS
    # -----------------------------------------

    if detection_results:

        for item in detection_results:

            report += f"{item}\n"

    else:

        report += (
            "No sensitive data detected\n"
        )

    # -----------------------------------------
    # RISK ANALYSIS
    # -----------------------------------------

    report += f"""

================================================
RISK ANALYSIS
================================================

Risk Level :
{risk_analysis['risk_level']}

Risk Score :
{risk_analysis['risk_score']}

RISK REASONS:
"""

    if not risk_analysis["reasons"]:

        report += (
            "- No significant risk indicators detected\n"
        )

    else:

        for reason in risk_analysis["reasons"]:

            report += f"- {reason}\n"

    # -----------------------------------------
    # THREAT CLASSIFICATION
    # -----------------------------------------

    report += f"""

================================================
THREAT CLASSIFICATION
================================================

Threat Category :
{threat_category}

Threat Family :
{threat_family}

Threat Type :
{threat_type}

Confidence :
{threat_confidence}

Priority :
{threat_priority}
"""

    # -----------------------------------------
    # INTENT ANALYSIS DETAILS
    # -----------------------------------------

    report += """

================================================
INTENT ANALYSIS DETAILS
================================================

INTENT REASONS:
"""

    for reason in intent_analysis["reasons"]:

        report += (
            f"\nDetected Phrase : "
            f"{reason['detected_phrase']}\n"
        )

        report += (
            f"Security Concern : "
            f"{reason['security_concern']}\n"
        )

        report += (
            f"Explanation : "
            f"{reason['explanation']}\n"
        )

    # -----------------------------------------
    # REPORT FOOTER
    # -----------------------------------------

    report += """

================================================
END OF FORENSIC ANALYSIS REPORT
================================================
"""

    # -----------------------------------------
    # RETURN FINAL REPORT
    # -----------------------------------------

    return report