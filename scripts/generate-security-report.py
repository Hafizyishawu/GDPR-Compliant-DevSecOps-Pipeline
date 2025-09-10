#!/usr/bin/env python3
"""
GDPR-Compliant DevSecOps Security Report Generator
Converts technical security scan results into executive-friendly HTML reports
"""

import json
import os
from datetime import datetime
from jinja2 import Template

class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'project_name': 'GDPR-Compliant DevSecOps Pipeline',
            'compliance_framework': 'UK GDPR + DevSecOps Best Practices',
            'total_files_scanned': 0,
            'security_issues': [],
            'compliance_status': 'COMPLIANT',
            'risk_level': 'LOW',
            'recommendations': []
        }

    def load_semgrep_results(self, filepath):
        """Parse Semgrep PII detection results"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            self.report_data['total_files_scanned'] = len(data.get('paths', {}).get('scanned', []))

            for result in data.get('results', []):
                issue = {
                    'type': 'GDPR Compliance Violation',
                    'severity': result['extra']['severity'],
                    'message': result['extra']['message'],
                    'file': result['path'],
                    'line': result['start']['line'],
                    'rule_id': result['check_id'],
                    'business_impact': self._get_business_impact(result['check_id']),
                    'remediation': self._get_remediation_advice(result['check_id'])
                }
                self.report_data['security_issues'].append(issue)

            # Determine overall risk level
            if len(data.get('results', [])) == 0:
                self.report_data['risk_level'] = 'LOW'
                self.report_data['compliance_status'] = 'COMPLIANT'
            elif any(r['extra']['severity'] == 'ERROR' for r in data.get('results', [])):
                self.report_data['risk_level'] = 'HIGH'
                self.report_data['compliance_status'] = 'NON-COMPLIANT'
            else:
                self.report_data['risk_level'] = 'MEDIUM'
                self.report_data['compliance_status'] = 'PARTIALLY COMPLIANT'

        except FileNotFoundError:
            print(f"Semgrep results file not found: {filepath}")
        except json.JSONDecodeError:
            print(f"Invalid JSON in Semgrep results: {filepath}")

    def load_gitleaks_results(self, filepath):
        """Parse GitLeaks secret detection results"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            for finding in data:
                issue = {
                    'type': 'Secret/PII Exposure',
                    'severity': 'HIGH',
                    'message': f"Potential {finding.get('Description', 'secret')} detected",
                    'file': finding.get('File', 'Unknown'),
                    'line': finding.get('StartLine', 0),
                    'rule_id': finding.get('RuleID', 'secret-detection'),
                    'business_impact': 'Data breach risk, ICO fine exposure (up to £20M)',
                    'remediation': 'Remove secret from code, rotate credentials, implement secrets management'
                }
                self.report_data['security_issues'].append(issue)
                self.report_data['risk_level'] = 'CRITICAL'
                self.report_data['compliance_status'] = 'NON-COMPLIANT'

        except FileNotFoundError:
            print(f"GitLeaks results file not found: {filepath}")
        except (json.JSONDecodeError, KeyError):
            print(f"Error parsing GitLeaks results: {filepath}")

    def load_vulnerability_scan(self, filepath):
        """Parse vulnerability scan results"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            # Parse Grype/Syft vulnerability results
            for match in data.get('matches', []):
                severity = match.get('vulnerability', {}).get('severity', 'UNKNOWN')
                if severity in ['HIGH', 'CRITICAL']:
                    issue = {
                        'type': 'Dependency Vulnerability',
                        'severity': severity,
                        'message': f"Vulnerable dependency: {match.get('artifact', {}).get('name', 'Unknown')}",
                        'file': 'package.json',
                        'line': 0,
                        'rule_id': match.get('vulnerability', {}).get('id', 'vuln-scan'),
                        'business_impact': f"Supply chain security risk, potential data exposure",
                        'remediation': f"Update to version {match.get('vulnerability', {}).get('fix', {}).get('versions', ['latest'])[0] if match.get('vulnerability', {}).get('fix') else 'latest'}"
                    }
                    self.report_data['security_issues'].append(issue)

        except FileNotFoundError:
            print(f"Vulnerability scan results not found: {filepath}")
        except (json.JSONDecodeError, KeyError):
            print(f"Error parsing vulnerability results: {filepath}")

    def _get_business_impact(self, rule_id):
        """Map technical violations to business impact"""
        impact_map = {
            'hardcoded-personal-data': 'GDPR Article 5 violation - ICO fine risk up to £20M, reputational damage',
            'detect-pii-in-logs': 'Data exposure in logs - breach notification requirement, compliance violation',
            'unencrypted-pii-storage': 'Article 32 violation - data security inadequacy, audit failure risk',
            'missing-consent-check': 'Article 6 violation - unlawful processing, subject access request complications',
            'missing-audit-log': 'Article 30 violation - inability to demonstrate compliance during audit'
        }
        return impact_map.get(rule_id.split('.')[-1], 'Potential compliance and security risk')

    def _get_remediation_advice(self, rule_id):
        """Provide specific remediation steps"""
        remediation_map = {
            'hardcoded-personal-data': 'Remove hardcoded PII, use environment variables or secure configuration',
            'detect-pii-in-logs': 'Implement PII filtering in logging, use structured logging with field redaction',
            'unencrypted-pii-storage': 'Implement field-level encryption for sensitive data in database',
            'missing-consent-check': 'Add consent validation before data processing operations',
            'missing-audit-log': 'Implement comprehensive audit logging for all data operations'
        }
        return remediation_map.get(rule_id.split('.')[-1], 'Review security best practices and implement appropriate controls')

    def generate_recommendations(self):
        """Generate executive recommendations based on findings"""
        if not self.report_data['security_issues']:
            self.report_data['recommendations'] = [
                'Continue current security practices',
                'Consider implementing additional monitoring for runtime security',
                'Schedule quarterly security reviews to maintain compliance posture'
            ]
        else:
            high_severity_count = len([i for i in self.report_data['security_issues'] if i['severity'] in ['HIGH', 'CRITICAL']])

            if high_severity_count > 0:
                self.report_data['recommendations'].extend([
                    f'IMMEDIATE ACTION: Address {high_severity_count} high/critical severity issues',
                    'Implement mandatory security training for development team',
                    'Review and strengthen code review processes'
                ])

            if any('GDPR' in issue['business_impact'] for issue in self.report_data['security_issues']):
                self.report_data['recommendations'].extend([
                    'Schedule legal review of data processing practices',
                    'Conduct GDPR compliance training for technical teams',
                    'Implement Data Protection Impact Assessment (DPIA) process'
                ])

    def generate_html_report(self):
        """Generate executive-friendly HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #333;
            font-size: 1.2em;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #dc3545; }
        .risk-critical { color: #6f42c1; }
        .compliant { color: #28a745; }
        .non-compliant { color: #dc3545; }
        .partially-compliant { color: #ffc107; }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .issue {
            background: #fff;
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 0 8px 8px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .issue.warning {
            border-left-color: #ffc107;
        }
        .issue.info {
            border-left-color: #17a2b8;
        }
        .issue h4 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .issue .severity {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity.high, .severity.critical {
            background: #dc3545;
            color: white;
        }
        .severity.medium {
            background: #ffc107;
            color: #333;
        }
        .severity.low {
            background: #28a745;
            color: white;
        }
        .recommendations {
            background: #e8f4fd;
            border: 1px solid #bee5eb;
            border-radius: 8px;
            padding: 20px;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        .footer {
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .no-issues {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            font-size: 1.1em;
        }
        .gdpr-badge {
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DevSecOps Security Assessment</h1>
            <p>GDPR-Compliant Pipeline Security Report</p>
            <p>Generated: {{ scan_date }}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Overall Risk Level</h3>
                <div class="value risk-{{ risk_level.lower() }}">{{ risk_level }}</div>
            </div>
            <div class="summary-card">
                <h3>Compliance Status</h3>
                <div class="value {{ compliance_status.lower().replace('-', '_') }}">{{ compliance_status }}</div>
            </div>
            <div class="summary-card">
                <h3>Security Issues</h3>
                <div class="value">{{ security_issues|length }}</div>
            </div>
            <div class="summary-card">
                <h3>Files Scanned</h3>
                <div class="value">{{ total_files_scanned }}</div>
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This automated security assessment evaluates our DevSecOps pipeline against UK GDPR requirements and cybersecurity best practices. The scan covers static code analysis, secret detection, dependency vulnerabilities, and GDPR compliance patterns.</p>

                {% if compliance_status == 'COMPLIANT' %}
                <div class="no-issues">
                    <strong>EXCELLENT:</strong> No security violations detected. The codebase demonstrates strong adherence to GDPR requirements and security best practices.
                </div>
                {% else %}
                <p><strong>Risk Assessment:</strong> {{ security_issues|length }} security issue(s) detected requiring attention. Immediate remediation recommended for high-severity findings to maintain compliance posture.</p>
                {% endif %}
            </div>

            {% if security_issues %}
            <div class="section">
                <h2>Security Findings</h2>
                {% for issue in security_issues %}
                <div class="issue">
                    <h4>
                        {{ issue.message }}
                        <span class="severity {{ issue.severity.lower() }}">{{ issue.severity }}</span>
                        {% if 'GDPR' in issue.business_impact %}
                        <span class="gdpr-badge">GDPR</span>
                        {% endif %}
                    </h4>
                    <p><strong>File:</strong> {{ issue.file }} (Line {{ issue.line }})</p>
                    <p><strong>Business Impact:</strong> {{ issue.business_impact }}</p>
                    <p><strong>Recommended Action:</strong> {{ issue.remediation }}</p>
                </div>
                {% endfor %}
            </div>
            {% endif %}

            <div class="section">
                <h2>Strategic Recommendations</h2>
                <div class="recommendations">
                    <ul>
                        {% for recommendation in recommendations %}
                        <li>{{ recommendation }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>

            <div class="section">
                <h2>Compliance Framework Coverage</h2>
                <ul>
                    <li><strong>UK GDPR Articles:</strong> 5 (Data minimization), 6 (Lawful basis), 15 (Access rights), 17 (Erasure), 25 (Privacy by design), 30 (Records), 32 (Security)</li>
                    <li><strong>Security Controls:</strong> Static code analysis, secret detection, dependency scanning, supply chain transparency</li>
                    <li><strong>Automated Compliance:</strong> Pre-commit hooks, CI/CD integration, continuous monitoring</li>
                    <li><strong>Risk Management:</strong> Vulnerability assessment, breach prevention, audit trail maintenance</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>This report was automatically generated by our GDPR-Compliant DevSecOps Pipeline</p>
            <p>For technical details, review the individual scan results in the security-reports directory</p>
        </div>
    </div>
</body>
</html>
        """

        template = Template(html_template)
        return template.render(**self.report_data)

def main():
    """Main report generation function"""
    os.makedirs('security-reports', exist_ok=True)

    generator = SecurityReportGenerator()

    # Load scan results
    generator.load_semgrep_results('security-reports/pii-scan.json')
    generator.load_gitleaks_results('security-reports/gitleaks-report.json')
    generator.load_vulnerability_scan('security-reports/vulnerabilities.json')

    # Generate recommendations
    generator.generate_recommendations()

    # Generate HTML report
    html_report = generator.generate_html_report()

    # Save report
    with open('security-reports/executive-report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)

    print("Executive security report generated: security-reports/executive-report.html")
    print(f"Report summary: {generator.report_data['compliance_status']} - {generator.report_data['risk_level']} risk")

if __name__ == "__main__":
    main()
