from datetime import datetime

def save_log(content):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("../data/logs/analysis_log.txt", "a") as file:

        file.write(f"\n[{timestamp}]\n")
        file.write(content)
        file.write("\n")