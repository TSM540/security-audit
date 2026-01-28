from setuptools import setup, find_packages

setup(
    name="security-audit",
    version="1.0.0",
    description="Security audit demonstration for CI/CD pipelines",
    author="Salim Tabellout",
    py_modules=["security_audit"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "security-audit=security_audit:run_security_audit",
        ],
    },
)