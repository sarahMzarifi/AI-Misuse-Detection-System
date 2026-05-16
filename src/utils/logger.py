from datetime import datetime

def save_log(content):

    # GENERATE FORENSIC TIMESTAMP

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # FORENSIC LOG HEADER

    log_entry = f"""
================================================
FORENSIC ANALYSIS RECORD
Timestamp : {timestamp}
================================================

{content}

================================================
END OF RECORD
================================================

"""
    # SAVE LOG ENTRY

    with open(
        "../data/logs/analysis_log.txt",
        "a"
    ) as file:

        file.write(log_entry)