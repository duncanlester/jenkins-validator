# 🔒 Jenkins Plugin Validator

> **Automated security scanning and validation for Jenkins plugins**

A pure Groovy Jenkins pipeline that validates installed plugins, scans for vulnerabilities, and generates comprehensive security reports.

## ✨ Features

- ✅ **Zero External Dependencies** - Pure Groovy/Jenkins native
- 🔍 **Vulnerability Scanning** - Check plugins against known CVE database
- 📊 **Risk Scoring** - Automated risk assessment (0-100 scale)
- 📝 **Beautiful Reports** - HTML and JSON format outputs
- 🔔 **Slack Notifications** - Real-time security alerts
- ⏰ **Scheduled Scans** - Daily automated validation at 2 AM UTC
- 📦 **Plugin Updates** - Track outdated plugins

## 🚀 Quick Start

### 1. Setup Jenkins Pipeline

1. Create a new **Pipeline** job in Jenkins
2. Point it to this repository
3. The `Jenkinsfile` will be automatically detected

### 2. Configure Slack (Optional)

Add Slack webhook URL as Jenkins credential:

```bash
# In Jenkins: Manage Jenkins > Credentials
ID: slack-webhook-url
Type: Secret text
Secret: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
