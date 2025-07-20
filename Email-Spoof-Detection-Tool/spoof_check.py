import re

def extract_field(headers, field_name):
    # Unfold headers (join multiline headers)
    unfolded = re.sub(r'\r?\n\s+', ' ', headers)
    pattern = rf"{field_name}:(.*?)(?=\n\S|$)"
    match = re.search(pattern, unfolded, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else "Not Found"

def get_domain(email_address):
    match = re.search(r'@([\w\.-]+)', email_address)
    return match.group(1).lower() if match else "unknown"

def get_origin_ip(headers):
    unfolded = re.sub(r'\r?\n\s+', ' ', headers)
    received_headers = re.findall(r"Received: (.*?)(?=\n\S|$)", unfolded, re.IGNORECASE | re.DOTALL)
    if received_headers:
        first_received = received_headers[-1]
        ip_match = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', first_received)
        return ip_match.group(1) if ip_match else "Not Found"
    return "Not Found"

def get_auth_results(headers):
    unfolded = re.sub(r'\r?\n\s+', ' ', headers)
    match = re.search(r"Authentication-Results:(.*?)(?=\n\S|$)", unfolded, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else "Not Found"

def extract_auth_value(auth_results, key):
    # Extract spf=..., dkim=..., dmarc=... from Authentication-Results string
    match = re.search(rf"{key}=([^\s\);]+)", auth_results, re.IGNORECASE)
    return match.group(1) if match else "Not Found"

def analyze_spoofing(headers):
    result = {}

    from_field = extract_field(headers, "From")
    return_path = extract_field(headers, "Return-Path")
    auth_results = get_auth_results(headers)
    origin_ip = get_origin_ip(headers)

    spf_result = extract_auth_value(auth_results, "spf")
    dkim_result = extract_auth_value(auth_results, "dkim")
    dmarc_result = extract_auth_value(auth_results, "dmarc")

    result["From"] = from_field
    result["Return-Path"] = return_path
    result["Origin IP"] = origin_ip
    result["Authentication-Results"] = auth_results
    result["SPF Result"] = spf_result
    result["DKIM Result"] = dkim_result
    result["DMARC Result"] = dmarc_result

    result["SPF Passed"] = spf_result.lower() == "pass"
    result["DKIM Passed"] = dkim_result.lower() == "pass"
    result["DMARC Passed"] = dmarc_result.lower() == "pass"

    spoofed = (
        not result["SPF Passed"]
        or not result["DKIM Passed"]
        or not result["DMARC Passed"]
    )
    result["Likely Spoofed"] = "Yes" if spoofed else "No"

    warnings = []
    from_domain = get_domain(from_field)
    return_domain = get_domain(return_path)

    if from_domain != return_domain:
        warnings.append("Return-Path domain doesn't match From domain")

    dkim_domain_match = re.search(r'header\.i=@([\w\.-]+)', auth_results)
    if dkim_domain_match and dkim_domain_match.group(1).lower() != from_domain:
        warnings.append("DKIM domain doesn't match From domain")

    result["Warnings"] = warnings if warnings else ["None"]

    return result
