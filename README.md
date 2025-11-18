# Syslog Anonymizer

**Browser-based Syslog Anonymizer: JavaScript tool to redact sensitive data from syslog messages locally—no server uploads, ensuring privacy for logs.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/syslog-anonymizer?style=social)](https://github.com/yourusername/syslog-anonymizer/stargazers)

Simple, zero-dependency JavaScript tool that anonymizes syslog messages directly in your browser.  
All processing happens client-side — your logs never leave your machine.

## Live Demo
[https://syslserve.com/SyslogAnonymizer.html](https://syslserve.com/anonymizer/tool/syslog-anonymizer.html)

## Features
- 100% client-side — no data uploaded anywhere  
- Fast regex-based redaction of common sensitive patterns  
- Currently anonymizes: IPv4 & IPv6 addresses, MAC addresses, email addresses, hostnames, usernames, process IDs, UUIDs  
- Preserves original log structure and timestamps  
- Copy-paste or drag-and-drop input  
- No build step, no dependencies — just open `SyslogAnonymizer.html`

## Quick Start

bash
git clone https://github.com/yourusername/syslog-anonymizer.git
cd syslog-anonymizer
# Open the main file
open SyslogAnonymizer.html    # macOS
start SyslogAnonymizer.html   # Windows
xdg-open SyslogAnonymizer.html # Linux

## Usage

Open SyslogAnonymizer.html in any modern browser  
Paste your syslog text or drop a log file  
Click “Anonymize”  
Copy the result or click “Download anonymized log”

## Customization

Edit the redaction rules directly in the JavaScript section:

```
const REDACTION_RULES = [
  { name: "IPv4",  regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,          replacement: "192.0.2.xxx" },
  { name: "Email", regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: "user@example.com" },
  // add your own rules here
];
```

## Contributing

Contributions are very welcome! Feel free to:
- Add new redaction patterns  
- Suggest performance improvements  
- Propose UI/UX enhancements  
- Add support for additional log formats

Just fork the repo, make your changes, and submit a pull request.


