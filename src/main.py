from services.analysis_service import analyze_prompt
from reporting.report_generator import generate_report
from utils.logger import save_log


# READ PROMPT DATASET

with open(
    "../data/raw_prompts/sample_prompts.txt",
    "r"
) as file:

    prompts = file.readlines()


# PROCESS EACH PROMPT

for idx, prompt in enumerate(prompts):

    prompt = prompt.strip()

    if not prompt:
        continue

    # CENTRALIZED CYBERSECURITY ANALYSIS

    analysis_result = analyze_prompt(
        prompt
    )

    # GENERATE FORENSIC REPORT

    forensic_report = generate_report(

        analysis_result,

        prompt_number=idx + 1
    )

    # TERMINAL OUTPUT

    print(forensic_report)

    # SAVE FORENSIC LOG

    save_log(forensic_report)