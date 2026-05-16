def generate_report(
    analysis_result,
    prompt_number=None
):

    # EXTRACT ANALYSIS COMPONENTS

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

    # REPORT HEADER

    report = f"""

================================================
FORENSIC PROMPT ANALYSIS REPORT
================================================

PROMPT NUMBER:
{prompt_number}

PROMPT:
{prompt}

================================================
DETECTION RESULTS
================================================
"""

    # DETECTION RESULTS

    if detection_results:

        for item in detection_results:

            report += f"{item}\n"

    else:

        report += (
            "No sensitive data detected\n"
        )

    # RISK ANALYSIS

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

    # INTENT ANALYSIS

    report += f"""

================================================
INTENT ANALYSIS
================================================

Intent Type :
{intent_analysis['intent_type']}

Severity :
{intent_analysis['severity']}

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

    # REPORT FOOTER

    report += """

================================================
END OF FORENSIC ANALYSIS REPORT
================================================
"""
    #RETURN FINAL REPORT

    return report