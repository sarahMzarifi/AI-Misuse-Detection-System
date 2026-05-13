from detectors.sensitive_detector import detect_sensitive_data
from classifiers.risk_classifier import classify_risk
from analyzers.intent_analyzer import analyze_intent
from utils.logger import save_log

# Read prompts
with open("../data/raw_prompts/sample_prompts.txt", "r") as file:
    prompts = file.readlines()

# Analyze prompts
for idx, prompt in enumerate(prompts):

    prompt = prompt.strip()

    if not prompt:
        continue

    # -----------------------------------------
    # DETECTION + ANALYSIS PIPELINE
    # -----------------------------------------

    findings = detect_sensitive_data(prompt)

    risk_analysis = classify_risk(findings, prompt)

    intent_analysis = analyze_intent(prompt)

    # -----------------------------------------
    # TERMINAL OUTPUT
    # -----------------------------------------

    print("\n================================================")

    print(f"PROMPT {idx+1}")
    print("------------------------------------------------")
    print(prompt)

    # -----------------------------------------
    # DETECTION RESULTS
    # -----------------------------------------

    print("\nDETECTION RESULTS")
    print("------------------------------------------------")

    if findings:

        for item in findings:
            print(item)

    else:
        print("No sensitive data detected")

    # -----------------------------------------
    # RISK ANALYSIS
    # -----------------------------------------

    print("\nRISK ANALYSIS")
    print("------------------------------------------------")

    print(f"Risk Level : {risk_analysis['risk_level']}")
    print(f"Risk Score : {risk_analysis['risk_score']}")

    print("\nRISK REASONS")
    print("------------------------------------------------")

    for reason in risk_analysis['reasons']:
        print(f"- {reason}")

    # -----------------------------------------
    # INTENT ANALYSIS
    # -----------------------------------------

    print("\nINTENT ANALYSIS")
    print("------------------------------------------------")

    print(f"Intent Type : {intent_analysis['intent_type']}")
    print(f"Severity    : {intent_analysis['severity']}")

    print("\nINTENT REASONS")
    print("------------------------------------------------")

    for reason in intent_analysis['reasons']:

        print(f"\nDetected Phrase : {reason['detected_phrase']}")

        print(
            f"Security Concern : {reason['security_concern']}"
        )

        print(
            f"Explanation : {reason['explanation']}"
        )

    # -----------------------------------------
    # STRUCTURED LOG GENERATION
    # -----------------------------------------

    log_content = f"""
PROMPT:
{prompt}

RISK LEVEL:
{risk_analysis['risk_level']}

RISK SCORE:
{risk_analysis['risk_score']}

INTENT TYPE:
{intent_analysis['intent_type']}

INTENT SEVERITY:
{intent_analysis['severity']}

RISK REASONS:
"""

    for reason in risk_analysis['reasons']:
        log_content += f"- {reason}\n"

    log_content += "\nINTENT REASONS:\n"

    for reason in intent_analysis['reasons']:

        log_content += (
            f"\nDetected Phrase : {reason['detected_phrase']}\n"
        )

        log_content += (
            f"Security Concern : "
            f"{reason['security_concern']}\n"
        )

        log_content += (
            f"Explanation : "
            f"{reason['explanation']}\n"
        )

    # -----------------------------------------
    # SAVE FORENSIC LOG
    # -----------------------------------------

    save_log(log_content)