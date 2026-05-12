import re

def detect_sensitive_data(text):

    findings = []

    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    # API key pattern
    api_pattern = r'sk-[A-Za-z0-9]+'

    # Password pattern
    password_pattern = r'password\s*=\s*\w+'

    # Detect matches
    emails = re.findall(email_pattern, text)
    apis = re.findall(api_pattern, text)
    passwords = re.findall(password_pattern, text)

    # Store findings
    if emails:
        findings.append(("EMAIL DETECTED", emails))

    if apis:
        findings.append(("API KEY DETECTED", apis))

    if passwords:
        findings.append(("PASSWORD DETECTED", passwords))

    return findings