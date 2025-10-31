from setuptools import setup, find_packages

setup(
    name="vuln-detective",
    version="1.0.0",
    description="AI-Powered Interactive Vulnerability Detection System",
    author="VulnDetective Team",
    author_email="contact@vulndetective.dev",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "openai>=1.0.0",
        "anthropic>=0.18.0",
        "python-dotenv>=1.0.0",
        "tree-sitter>=0.20.0",
        "astroid>=3.0.0",
        "bandit>=1.7.5",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "sarif-om>=1.0.4",
        "markdown>=3.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "vulndetective=cli:main",
        ]
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
