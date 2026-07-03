import os, subprocess, hashlib, requests

def handler(request):
    host = request.args.get("host")
    os.system("ping -c 1 " + host)                          # command injection (CWE-78)
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % host)  # SQL injection (CWE-89)
    requests.get(request.args.get("url"), verify=False)     # SSRF + disabled TLS (CWE-918/295)
    open("/data/" + request.args.get("f"))                  # path traversal (CWE-22)
    hashlib.md5(host.encode())                              # weak hash (CWE-327)

    # SAFE variants — must NOT be flagged
    subprocess.run(["ping", "-c", "1", "8.8.8.8"])
    requests.get("https://api.example.com", verify=True)
