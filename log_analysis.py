import re
import csv
from collections import Counter, defaultdict

# Define the threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

# Function to parse log file
def parse_log(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(r'\"(?:GET|POST) (.*?) HTTP/1\.1\"', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Check for failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

# Function to save results to CSV
def save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

# Main function to analyze log file
def analyze_log(file_path):
    # Parse log file
    ip_requests, endpoint_requests, failed_login_attempts = parse_log(file_path)

    # Most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Filter suspicious IPs
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    # Print results
    print("Requests per IP Address:")
    for ip, count in ip_requests.items():
        print(f"{ip} - {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip} - {count} failed login attempts")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, 'log_analysis_results.csv')

# Run the script
if __name__ == "__main__":
    log_file_path = 'sample.log'
    analyze_log(log_file_path)
