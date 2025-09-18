import os
import re
from datetime import datetime

class ReportGenerator:
    def __init__(self, target):
        self.target = target
        
        # Sanitize filename (safe for Windows/Linux)
        safe_target = re.sub(r'[^\w\-_.]', '_', target)
        self.filename = f"results/report_{safe_target}.txt"
        self.lines = []

        # Only add report header if file does not exist (first run)
        if not os.path.exists(self.filename):
            self.add_line("REDVECTOR - Vulnerability Assessment Report")
            self.add_line("=" * 45)
            self.add_line(f"Target: {self.target}")
            self.add_line("")

    def add_line(self, text):
        self.lines.append(text)

    def add_section(self, title, content_lines):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.add_line(f"\n[ {title} ] - {timestamp}")
        self.add_line("-" * (len(title) + len(timestamp) + 5))
        self.lines.extend(content_lines)

    def save(self):
        os.makedirs("results", exist_ok=True)
        # Append instead of overwrite
        with open(self.filename, "a", encoding="utf-8") as f:
            f.write("\n".join(self.lines) + "\n")
        print(f"\n[📄] Report updated: {self.filename}")
