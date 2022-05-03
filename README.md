# linux-hardening
Linux auditing &amp; hardening for Debian/Ubuntu.



## Description

The tool is still in development, some features may be missing.

For now, it is designed for the following Linux systems:

- Ubuntu 20.04 LTS
- Debian 10

Other distributions will be supported soon!



It lets you do the following:

- Audit your system
- Fix vulnerabilities found by audit.
- Save a report in a .txt / .md / .csv file



## Requirements

- Python 3.x is required. You can check if Python 3.x is installed with the command ```python3 --version```
- The package installer Pip is required. If it's not the case, please run the command ```sudo apt update && sudo apt install python3-pip```
- Then, from the tool directory, please install required packages with the command ```pip install -r requirements.txt```.

Finally, when these requirements are met, you can run the tool with the command as sudo, with the command ```sudo python3 hardening.py```.

