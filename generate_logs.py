import time
import random

def generate_fake_logs(filepath="access.log"):
    normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]
    attacker_ip = "10.0.0.99"

    with open(filepath, "w") as f:
        for _ in range(30):
            ip = random.choice(normal_ips)
            f.write(f'{ip} - - [20/Aug/2026:14:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024\n')
        
        for _ in range(50):
            f.write(f'{attacker_ip} - - [20/Aug/2026:14:00:05 +0000] "POST /login HTTP/1.1" 401 512\n')

if __name__ == "__main__":
    generate_fake_logs()