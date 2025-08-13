import requests
import sys
import os

def sanitize_filename(url):
    return url.replace("https://", "").replace("http://", "").replace("/", "_")

def generate_poc_html(url, output_dir="poc"):
    filename = sanitize_filename(url) + ".html"
    filepath = os.path.join(output_dir, filename)

    html_content = f"""
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC - {url}</title></head>
<body>
    <h1>Clickjacking Test: {url}</h1>
    <iframe src="{url}" width="800" height="600" style="opacity:0.8;"></iframe>
</body>
</html>
    """

    os.makedirs(output_dir, exist_ok=True)
    with open(filepath, "w") as f:
        f.write(html_content)
    print(f"[+] PoC saved at: {filepath}")

def detect_clickjacking(url):
    try:
        response = requests.get(url, timeout=10)

        x_frame_options = response.headers.get("X-Frame-Options", "")
        csp = response.headers.get("Content-Security-Policy", "")

        print(f"\n[+] Checking: {url}")
        print("[*] Headers found:")
        print(f"    X-Frame-Options: {x_frame_options or 'Not found'}")
        print(f"    Content-Security-Policy: {csp or 'Not found'}")

        vulnerable = False
        if "DENY" not in x_frame_options.upper() and "SAMEORIGIN" not in x_frame_options.upper():
            if "frame-ancestors" not in csp.lower():
                vulnerable = True

        if vulnerable:
            print("[!] Vulnerable to Clickjacking!")
            generate_poc_html(url)
        else:
            print("[✔] Protected against Clickjacking.")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error accessing {url}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_clickjacking.py urls.txt")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
            for target in targets:
                detect_clickjacking(target)
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
