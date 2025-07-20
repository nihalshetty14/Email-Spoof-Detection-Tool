import os
from utils import load_headers
from spoof_check import analyze_spoofing
from colorama import init, Fore, Style

init(autoreset=True)

def display_result(result, case_name):
    print(Fore.CYAN + f"\n--- Email Spoofing Analysis: {case_name} ---\n")

    for key, value in result.items():
        if key == "Likely Spoofed":
            icon = "🚨" if value == "Yes" else "✅"
            color = Fore.RED if value == "Yes" else Fore.GREEN
            print(f"{color}{key}: {value} {icon}")
        elif key.endswith("Passed"):
            icon = "✅" if value else "❌"
            color = Fore.GREEN if value else Fore.RED
            print(f"{color}{key}: {'Pass' if value else 'Fail'} {icon}")
        elif key == "Warnings":
            print(f"{Fore.MAGENTA}{key}:")
            for warn in value:
                print(f"{Fore.YELLOW}  ⚠️ {warn}")
        else:
            print(f"{Fore.YELLOW}{key}: {Style.RESET_ALL}{value}")

def save_report(result, case_name):
    os.makedirs("output_reports", exist_ok=True)
    output_path = os.path.join("output_reports", case_name.replace(".txt", "_report.txt"))

    with open(output_path, 'w') as f:
        for key, value in result.items():
            if isinstance(value, list):
                f.write(f"{key}:\n")
                for item in value:
                    f.write(f"  - {item}\n")
            else:
                f.write(f"{key}: {value}\n")
    print(Fore.GREEN + f"Report saved: {output_path}")

def main():
    folder = "test_cases"
    files = [f for f in os.listdir(folder) if f.endswith(".txt")]

    if not files:
        print(Fore.RED + "No .txt files found in 'test_cases' folder!")
        return

    for file in files:
        path = os.path.join(folder, file)
        headers = load_headers(path)
        result = analyze_spoofing(headers)
        display_result(result, file)
        save_report(result, file)

if __name__ == "__main__":
    main()
