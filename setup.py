from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="sdanalyzer",
    version="0.1.7",
    description="Tool to analyze APK files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Te-k/sdanalyzer",
    author="Tek",
    author_email="tek@randhome.io",
    keywords="osint",
    include_package_data=True,
    install_requires=[
        "Flask==3.0.3",
        "Flask-WTF==1.2.1",
        "peewee==3.17.6",
        "androguard==4.1.2",
        "requests",
        "yara-python==4.5.1",
        "virustotal-python==1.0.2",
    ],
    python_requires=">=3.7",
    license="GPLv3",
    packages=["sdanalyzer", "sdanalyzer.templates", "sdanalyzer.data"],
    package_data={"sdanalyzer": ["sdanalyzer/data/*", "sdanalyzer/templates/*"]},
    entry_points={"console_scripts": ["sdanalyzer=sdanalyzer.main:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
