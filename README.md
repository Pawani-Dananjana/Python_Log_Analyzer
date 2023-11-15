# Python_Log_Analyzer

## Description
This Python script analyzes firewall logs, generates a comprehensive report, and optionally creates a PDF report if it is needed by the user. A summery of the findings along with the recommendations is available in the Summary Report with Insights and Recommendations.pdf.

## Features
- Parses firewall logs from a text file.
- Generates a CSV file containing parsed log data.
- Analyzes logs to provide insights into traffic, potential attacks.
- Generates a detailed textual report.
- Optionally generates a PDF report if the user chooses.

## Prerquisits
- Python 3.x
- (Optional) FPDF module for PDF generation

## Usage
1. Clone the repository:
    ```bash
    [git clone https://github.com/yourusername/firewall-log-analyzer.git](https://github.com/Pawani-Dananjana/Python_Log_Analyzer.git)
    cd firewall-log-analyzer
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Run the script:
    ```bash
    python firewall_log_analyzer.py
    ```

4. Follow the prompts to input the firewall log file and choose whether to generate a PDF report.

## Configuration
- Modify `firewall_log.txt` with the path to your actual firewall log file.
- (Optional) Modify `firewall_log.csv` and `firewall_log_analysis_report.pdf` for desired CSV and PDF file paths.

## License
This project is licensed under the [MIT License](LICENSE).

## Author
Pawani_Dananjana

Feel free to contribute, report issues, or suggest improvements!

