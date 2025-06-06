from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QSpinBox, QDoubleSpinBox, QHBoxLayout, QProgressBar, QMessageBox
)
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import sys
import json
from vuln_scanner import VulnerabilityScanner


class ScannerWorker(QObject):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    done_signal = pyqtSignal(dict)

    def __init__(self, url, threads, delay):
        super().__init__()
        self.url = url
        self.threads = threads
        self.delay = delay

    def log(self, message):
        self.log_signal.emit(message)

    def run_scan(self):
        try:
            scanner = VulnerabilityScanner(
                self.url,
                threads=self.threads,
                delay=self.delay,
                log_callback=self.log
            )
            self.progress_signal.emit(10)
            report = scanner.run_scan()
            self.progress_signal.emit(100)
            self.done_signal.emit(report)
        except Exception as e:
            self.log(f"[ERROR] Scan failed: {str(e)}")


class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Web Vulnerability Scanner")
        self.setGeometry(200, 200, 700, 500)
        self.report = None
        self.thread = None

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Target Configuration"))
        layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com")
        layout.addWidget(self.url_input)

        config_layout = QHBoxLayout()
        self.threads_input = QSpinBox()
        self.threads_input.setValue(10)
        self.delay_input = QDoubleSpinBox()
        self.delay_input.setValue(1.0)
        self.delay_input.setSingleStep(0.1)
        config_layout.addWidget(QLabel("Threads:"))
        config_layout.addWidget(self.threads_input)
        config_layout.addWidget(QLabel("Delay (s):"))
        config_layout.addWidget(self.delay_input)
        layout.addLayout(config_layout)

        layout.addWidget(QLabel("Scan Output:"))
        self.output_console = QTextEdit()
        self.output_console.setStyleSheet("background-color: #111; color: #0f0;")
        self.output_console.setReadOnly(True)
        layout.addWidget(self.output_console)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)

        self.save_button = QPushButton("Save Report")
        self.save_button.clicked.connect(self.save_report)
        button_layout.addWidget(self.save_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def log_output(self, text):
        self.output_console.append(text)

    def update_progress(self, value):
        self.progress.setValue(value)

    def show_summary(self, report):
        self.report = report
        info = report['scan_info']
        self.log_output("\n========== SCAN SUMMARY ==========")
        self.log_output(f"Target: {info['target']}")
        self.log_output(f"Total Vulnerabilities: {info['total_vulnerabilities']}")
        self.log_output(f"High Severity: {info['severity']['HIGH']}")
        self.log_output(f"Medium Severity: {info['severity']['MEDIUM']}")
        self.log_output(f"Low Severity: {info['severity']['LOW']}")
        self.log_output(f"Forms Found: {report['forms_found']}")
        self.log_output(f"Links Found: {report['links_found']}")
        self.log_output("==================================\n")
        QMessageBox.information(self, "Scan Complete", "Vulnerability scan completed successfully!")

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url.startswith("http"):
            url = "http://" + url
        threads = self.threads_input.value()
        delay = self.delay_input.value()

        self.output_console.clear()
        self.progress.setValue(0)

        self.thread = QThread()
        self.worker = ScannerWorker(url, threads, delay)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run_scan)
        self.worker.log_signal.connect(self.log_output)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.done_signal.connect(self.show_summary)
        self.worker.done_signal.connect(self.thread.quit)
        self.worker.done_signal.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def save_report(self):
        if self.report:
            with open("gui_saved_report.json", "w") as f:
                json.dump(self.report, f, indent=2)
            self.log_output("[INFO] Report saved to gui_saved_report.json")
        else:
            self.log_output("[ERROR] No report to save!")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerGUI()
    window.show()
    sys.exit(app.exec_())
