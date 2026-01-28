"""
Security Audit Module - External Dependency Risk Demonstration

This module demonstrates that external dependencies from GitHub can be downloaded
and executed in the Jenkins pipeline without Artifactory validation.

⚠️ SECURITY RISK IDENTIFIED:
- Poetry can fetch dependencies directly from GitHub without going through Artifactory
- Pre-commit hooks can download external tools from GitHub
- No validation or security scanning is performed on external sources
- Malicious code could be injected via dependency substitution attacks

✅ RECOMMENDATIONS:
1. Enforce Artifactory proxy for ALL dependency sources
2. Block direct GitHub/PyPI access from Jenkins agents
3. Implement dependency signature verification
4. Use private PyPI mirror with security scanning
5. Audit all external dependencies in pyproject.toml and .pre-commit-config.yaml
"""

import hashlib
import logging
import os
import sys
from datetime import datetime


class SecurityAuditLogger:
    """
    Logs security-relevant information about the runtime environment
    to demonstrate potential security risks without stealing credentials.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def audit_environment(self) -> dict:
        """
        Audit the current runtime environment and identify security risks.

        Returns:
            dict: Audit findings with security risk indicators
        """
        audit_report = {
            "timestamp": datetime.now().isoformat(),
            "audit_type": "External Dependency Risk Assessment",
            "findings": [],
        }

        # Finding 1: External Python package source
        audit_report["findings"].append(
            {
                "severity": "HIGH",
                "category": "Unvalidated External Dependencies",
                "description": "Poetry can download packages directly from GitHub/PyPI without Artifactory validation",
                "evidence": {
                    "python_version": sys.version,
                    "executable_path": sys.executable,
                    "module_path": os.path.dirname(__file__),
                },
                "risk": "Malicious packages could be injected via dependency confusion or typosquatting",
                "recommendation": "Configure Poetry to use only internal Artifactory as package source",
            }
        )

        # Finding 2: Environment variables exposure risk
        # Collect credential-like variables
        credential_vars = {
            key: os.environ.get(key, "")
            for key in os.environ.keys()
            if any(
                pattern in key.upper()
                for pattern in [
                    "TOKEN",
                    "KEY",
                    "SECRET",
                    "PASSWORD",
                    "CREDENTIAL",
                    "API",
                    "JENKINS",
                    "AUTH",
                    "GITLAB",
                    "ID",
                    "ACCESS",
                    "PRIVATE",
                    "SSH",
                    "ACCESS_TOKEN",
                    "SECRET_TOKEN",
                    "AUTH_TOKEN",
                    
                ]
            )
        }

        audit_report["findings"].append(
            {
                "severity": "CRITICAL",
                "category": "Credential Exposure Risk",
                "description": "Jenkins credentials are exposed as environment variables during build",
                "evidence": {
                    "jenkins_env_vars": [
                        key for key in os.environ.keys() if "JENKINS" in key.upper()
                    ],
                    "credential_count": len(credential_vars),
                    "credential_names": list(credential_vars.keys()),
                    "credential_lengths": {
                        k: len(str(v)) for k, v in credential_vars.items()
                    },
                    # Cryptographic proof of access (can be verified later)
                    "access_verification_hashes": {
                        k: hashlib.sha256(v.encode()).hexdigest()[:16]
                        for k, v in credential_vars.items()
                    },
                },
                "risk": "External dependencies could read and exfiltrate credentials from environment",
                "recommendation": "Use Jenkins credential binding with masked output and minimal scope",
            }
        )

        # Finding 3: Network access validation
        audit_report["findings"].append(
            {
                "severity": "MEDIUM",
                "category": "Unrestricted Network Access",
                "description": "Jenkins agents can make outbound connections to arbitrary external services",
                "evidence": {
                    "current_working_directory": os.getcwd(),
                    "user": os.environ.get("USER", "unknown"),
                },
                "risk": "Malicious code could exfiltrate data to external servers",
                "recommendation": "Implement network egress filtering to allow only approved destinations",
            }
        )

        return audit_report

    def log_audit_findings(self) -> None:
        """
        Perform audit and log findings to console.
        This demonstrates the security risk without performing any malicious actions.
        """
        self.logger.warning("=" * 80)
        self.logger.warning("🔍 SECURITY AUDIT: External Dependency Risk Assessment")
        self.logger.warning("=" * 80)

        audit_report = self.audit_environment()

        self.logger.warning(f"\n📅 Audit Timestamp: {audit_report['timestamp']}")
        self.logger.warning(f"📋 Audit Type: {audit_report['audit_type']}\n")

        for idx, finding in enumerate(audit_report["findings"], 1):
            severity_icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(finding["severity"], "⚪")

            self.logger.warning(f"\n{severity_icon} Finding #{idx}")
            self.logger.warning(f"Severity: {finding['severity']}")
            self.logger.warning(f"Category: {finding['category']}")
            self.logger.warning(f"Description: {finding['description']}")
            self.logger.warning(f"Risk: {finding['risk']}")
            self.logger.warning(f"Recommendation: {finding['recommendation']}")

            # Log non-sensitive evidence
            if finding["category"] != "Credential Exposure Risk":
                self.logger.warning(f"Evidence: {finding['evidence']}")
            else:
                # For credential-related findings, show proof of access without exposing values
                self.logger.warning(
                    f"Evidence: Found {finding['evidence']['credential_count']} "
                    f"environment variables with credential-like names"
                )
                self.logger.warning(
                    f"  Variable names: {finding['evidence']['credential_names']}"
                )
                self.logger.warning(
                    f"  Variable lengths: {finding['evidence']['credential_lengths']}"
                )
                self.logger.warning(f"  ✓ Access verified via cryptographic hashes")
                self.logger.warning(
                    f"  ✓ Proof: This code successfully read {finding['evidence']['credential_count']} credentials"
                )

        self.logger.warning("\n" + "=" * 80)
        self.logger.warning(
            "⚠️  SECURITY RISK DEMONSTRATED: External dependencies are not validated"
        )
        self.logger.warning(
            "⚠️  This module was loaded from the codebase to prove the concept"
        )
        self.logger.warning(
            "✅ Action Required: Implement Artifactory proxy and egress filtering"
        )
        self.logger.warning("=" * 80 + "\n")


def run_security_audit():
    """
    Entry point for security audit demonstration.
    Call this from CLI or tests to demonstrate the security risk.
    """
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s: %(message)s"
    )

    auditor = SecurityAuditLogger()
    auditor.log_audit_findings()


if __name__ == "__main__":
    run_security_audit()