vHunter: Advanced Web Vulnerability Scanner

vHunter is a Python-based tool designed to identify and report security vulnerabilities in web applications. 
It combines a user-friendly PyQt5 GUI with a robust scanning engine, allowing security professionals and developers 
to assess the security of their web assets efficiently and effectively.

Features
--------

- Graphical User Interface: Built with PyQt5 for ease of use and accessibility.
- Automated Scanning: Detects common vulnerabilities like SQL Injection and Reflected Cross-Site Scripting (XSS).
- Customizable Parameters: Supports threading and request delays to control scan performance.
- Real-Time Feedback: Displays live output and progress through a console view and progress bar.
- Detailed Reporting: Generates structured JSON reports with severity classification.
- Report Exporting: Easily save and share scan results for future analysis.

Getting Started
---------------

1. Installation

Ensure Python 3.8 or newer is installed on your system. Then install dependencies:

    pip install -r requirements.txt

2. Run the Application

To start the GUI application:

    python gui_scanner.py

3. Create an Executable (Optional)

To build a standalone Windows executable:

    pip install pyinstaller
    pyinstaller --noconfirm --windowed --add-data "vuln_scanner.py;." gui_scanner.py

The executable will be located in the dist/ folder.

Project Structure
-----------------

    vHunter/
    ├── gui_scanner.py       - GUI application interface
    ├── vuln_scanner.py      - Core scanning logic
    ├── requirements.txt     - Python package dependencies
    └── README.md            - Project overview and instructions

Legal Disclaimer
----------------

vHunter is intended for authorized security testing and educational use only. Scanning systems without proper 
authorization is unethical and may be illegal. Use this tool responsibly.

Credits
-------

Created by Anantha Krishnan K.  
