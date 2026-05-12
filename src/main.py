from detectors.sensitive_detector import detect_sensitive_data

# Open prompt dataset
with open("../data/raw_prompts/sample_prompts.txt", "r") as file:
    prompts = file.readlines()

# Analyze prompts
for idx, prompt in enumerate(prompts):

    result = detect_sensitive_data(prompt)

    print("\n--------------------------------")

    print(f"Prompt {idx+1}:")
    print(prompt.strip())

    if result:

        print("\nSensitive Data Found:")

        for item in result:
            print(item)

    else:
        print("\nNo sensitive data detected.")