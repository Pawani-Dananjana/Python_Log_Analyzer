import re
import csv
from collections import defaultdict
from fpdf import FPDF

def parse_firewall_log(log_file):
    logs = []
    with open(log_file, 'r') as file:
        for line in file:
            if line.startswith("#"):
                continue
            fields = re.split(r'\s+', line.strip())
            log_entry = {
                'Date': fields[0],
                'Time': fields[1],
                'Action': fields[2],
                'Protocol': fields[3],
                'Src_IP': fields[4],
                'Dst_IP': fields[5],
                'Src_Port': fields[6],
                'Dst_Port': fields[7],
                'Size': int(fields[8]),  # Convert size to integer for sorting
                'TCP_Flags': fields[9] if fields[9] != '-' else '',
                'Info': re.sub(r'\s*-\s*', '', ' '.join(fields[10:]))
            }
            logs.append(log_entry)
    return logs

def save_to_csv(logs, csv_filename):
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = logs[0].keys()
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for log in logs:
            # Replace "-" with blank spaces in the 'Info' column
            log['Info'] = log['Info'].replace('-', '')
            writer.writerow(log)

def analyze_firewall_logs(logs):
    analysis_result = {
        'TotalLogs': len(logs),
        'AllowedLogs': sum(1 for log in logs if log['Action'] == 'ALLOW'),
        'BlockedLogs': sum(1 for log in logs if log['Action'] == 'BLOCK'),
        'TopSourceIPs': defaultdict(int),
        'TopDestinationIPs': defaultdict(int),
        'TopProtocols': defaultdict(int),
        'PotentialAttacks': [],
        'TCPFlags': defaultdict(int),
        'InternalTraffic': 0,
        'InboundExternalTraffic': 0,
        'OutboundExternalTraffic': 0,
        'SourcePorts': defaultdict(int),
        'DestinationPorts': defaultdict(int)
    }

    for log in logs:
        analysis_result['TopSourceIPs'][log['Src_IP']] += 1
        analysis_result['TopDestinationIPs'][log['Dst_IP']] += 1
        analysis_result['TopProtocols'][log['Protocol']] += 1

        if log['Action'] == 'BLOCK':
            analysis_result['PotentialAttacks'].append(log)

        tcp_flags = log['TCP_Flags'] if log['TCP_Flags'] != '-' else ''
        analysis_result['TCPFlags'][tcp_flags] += 1

        # Replace "-" with blank spaces in the 'Info' column
        log['Info'] = log['Info'].replace('-', '')

        if log['Src_IP'][:7] != '192.168':
            analysis_result['InboundExternalTraffic'] += 1
        elif log['Dst_IP'][:7] != '192.168':
            analysis_result['OutboundExternalTraffic'] += 1
        else:
            analysis_result['InternalTraffic'] += 1

        log['TrafficType'] = get_traffic_type(log)

        if log['Src_Port'] != '-':
            analysis_result['SourcePorts'][log['Src_Port']] += 1
        if log['Dst_Port'] != '-':
            analysis_result['DestinationPorts'][log['Dst_Port']] += 1

    return analysis_result

def get_traffic_type(log):
    if log['Src_IP'][:7] != '192.168':
        return 'Inbound External Traffic'
    elif log['Dst_IP'][:7] != '192.168':
        return 'Outbound External Traffic'
    else:
        return 'Internal Traffic'

def generate_report(analysis_result):
    report = "Firewall Log Analysis Report:\n"
    report += "-------------------------------\n"
    report += f"Total Logs: {analysis_result['TotalLogs']}\n"
    report += f"Allowed Logs: {analysis_result['AllowedLogs']}\n"
    report += f"Blocked Logs: {analysis_result['BlockedLogs']}\n\n"

    report += "Top Source IPs:\n"
    for ip, count in analysis_result['TopSourceIPs'].items():
        report += f"{ip}: {count} logs\n"

    report += "\nTop Destination IPs:\n"
    for ip, count in analysis_result['TopDestinationIPs'].items():
        report += f"{ip}: {count} logs\n"

    report += "\nTop Protocols:\n"
    for protocol, count in analysis_result['TopProtocols'].items():
        report += f"{protocol}: {count} logs\n"

    report += "\nPotential Attacks:\n"
    for log in analysis_result['PotentialAttacks']:
        report += f"{log['Date']} {log['Time']} - {log['Src_IP']} -> {log['Dst_IP']} ({log['Protocol']}) - {log['Info']} - Size: {log['Size']} bytes\n"

    report += "\nTCP Flags:\n"
    for flag, count in analysis_result['TCPFlags'].items():
        if flag != '':
            report += f"{flag}: {count} occurrences\n"

    report += f"\nInternal Traffic: {analysis_result['InternalTraffic']} logs\n"
    report += f"Inbound External Traffic: {analysis_result['InboundExternalTraffic']} logs\n"
    report += f"Outbound External Traffic: {analysis_result['OutboundExternalTraffic']} logs\n"

    report += "\nTraffic Type Details:\n"

    # Internal Traffic Details
    report += "\nInternal Traffic:\n"
    internal_traffic_details = generate_traffic_type_details(analysis_result['PotentialAttacks'], 'Internal Traffic')
    report += internal_traffic_details if internal_traffic_details else "No Data.\n"

    # Inbound External Traffic Details
    report += "\nInbound External Traffic:\n"
    inbound_external_traffic_details = generate_traffic_type_details(analysis_result['PotentialAttacks'], 'Inbound External Traffic')
    report += inbound_external_traffic_details if inbound_external_traffic_details else "No Data.\n"

    # Outbound External Traffic Details
    report += "\nOutbound External Traffic:\n"
    outbound_external_traffic_details = generate_traffic_type_details(analysis_result['PotentialAttacks'], 'Outbound External Traffic')
    report += outbound_external_traffic_details if outbound_external_traffic_details else "No Data.\n"

    # Source Ports
    report += "\nSource Ports:\n"
    source_ports_details = generate_port_details(analysis_result['SourcePorts'])
    report += source_ports_details if source_ports_details else "No Data.\n"

    # Destination Ports
    report += "\nDestination Ports:\n"
    destination_ports_details = generate_port_details(analysis_result['DestinationPorts'])
    report += destination_ports_details if destination_ports_details else "No Data.\n"

    # Size Details
    report += "\nTraffic Size Details:\n"
    size_details = generate_size_details(analysis_result['PotentialAttacks'])
    report += size_details if size_details else "No Data.\n"

    return report

def generate_traffic_type_details(data, traffic_type):
    details = ""
    filtered_data = [log for log in data if log['TrafficType'] == traffic_type]
    if not filtered_data:
        details += "No Data."
    else:
        for log in filtered_data:
            details += f"{log['Date']} {log['Time']} - {log['Src_IP']} -> {log['Dst_IP']} ({log['Protocol']}) - {log['Info']} - Size: {log['Size']} bytes\n"
    return details

def generate_port_details(port_data):
    details = ""
    sorted_ports = sorted(port_data.items(), key=lambda x: x[1], reverse=True)
    for port, count in sorted_ports:
        if port != '-':
            details += f"Port {port}: {count} occurrences\n"
    return details

def generate_size_details(data):
    details = ""
    sorted_data = sorted(data, key=lambda x: x['Size'], reverse=True)
    for log in sorted_data:
        details += f"{log['Date']} {log['Time']} - {log['Src_IP']} -> {log['Dst_IP']} ({log['Protocol']}) - {log['Info']} - Size: {log['Size']} bytes\n"
    return details

def generate_pdf_report(report, pdf_filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, report)
    pdf.output(pdf_filename)

if __name__ == "__main__":
    log_file = "firewall_log.txt"  # Replace with the actual firewall log file path
    csv_filename = "firewall_log.csv"  # Replace with the desired CSV file path
    pdf_filename = "firewall_log_analysis_report.pdf"  # Replace with the desired PDF file path

    firewall_logs = parse_firewall_log(log_file)

    # Save logs to CSV
    save_to_csv(firewall_logs, csv_filename)

    # Analyze logs
    analysis_result = analyze_firewall_logs(firewall_logs)

    # Generate and print the report
    report = generate_report(analysis_result)
    print(report)

    # Ask the user if they want to generate a PDF report
    generate_pdf = input("Do you want to generate a PDF report? (yes/no): ").lower()
    if generate_pdf == 'yes':
        generate_pdf_report(report, pdf_filename)
        print(f"PDF report saved to {pdf_filename}")
