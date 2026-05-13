from detectors.sensitive_detector import detect_sensitive_data
from classifiers.risk_classifier import classify_risk
from utils.logger import save_log

# Read prompts
with open("../data/raw_prompts/sample_prompts.txt", "r") as file:
    prompts = file.readlines()

# Analyze prompts
for idx, prompt in enumerate(prompts):

    prompt = prompt.strip()

    if not prompt:
        continue

    findings = detect_sensitive_data(prompt)

    risk_analysis = classify_risk(findings, prompt)

    print("\n================================================")

    print(f"PROMPT {idx+1}")
    print("------------------------------------------------")
    print(prompt)

    print("\nDETECTION RESULTS")
    print("------------------------------------------------")

    if findings:
        for item in findings:
            print(item)

    else:
        print("No sensitive data detected")

    print("\nRISK ANALYSIS")
    print("------------------------------------------------")
    print(f"Risk Level : {risk_analysis['risk_level']}")
    print(f"Risk Score : {risk_analysis['risk_score']}")

    print("\nREASONS")
    print("------------------------------------------------")

    for reason in risk_analysis['reasons']:
        print(f"- {reason}")
log_content = f"""
PROMPT:
{prompt}

RISK LEVEL:
{risk_analysis['risk_level']}

RISK SCORE:
{risk_analysis['risk_score']}

REASONS:
"""

for reason in risk_analysis['reasons']:
    log_content += f"- {reason}\n"

save_log(log_content)