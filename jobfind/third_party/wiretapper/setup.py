from setuptools import setup, find_packages

with open("WireTapper.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="wiretaper",
    version="1.0.0",
    description="Wireless OSINT & Signal Intelligence Platform",
    author="WireTapper Developer",
    packages=find_packages(),
    py_modules=["app", "cli", "telemetry_importer", "flock_manager"],
    include_package_data=True,
    package_data={
        "": ["templates/*", "templates/*/*", "static/*", "static/*/*", "uploads/*", "uploads/*/*"],
    },
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wiretapper = cli:main",
            "wiretaper = cli:main",
        ],
    },
    python_requires=">=3.8",
)
