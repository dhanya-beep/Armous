import time
from collections import defaultdict, deque
import statistics
import re

class TrafficAnalyzer:
    def __init__(self, rate_limit=10, window_seconds=60, anomaly_score_threshold=5):
        # Stores request data per IP: (timestamp, path, method, form_submission_flag)
        self.request_logs = defaultdict(lambda: deque(maxlen=10000))
        self.rate_limit = rate_limit  # Max allowed requests within window
        self.window_seconds = window_seconds  # Time window for rate limiting
        self.anomaly_score_threshold = anomaly_score_threshold
        self.current_sessions = defaultdict(list)  # Session timestamps per IP

    def log_request(self, client_ip, path, method, timestamp, form_submission=False):
        # Log incoming request and timestamp for session tracking
        self.request_logs[client_ip].append((timestamp, path, method, form_submission))
        self.current_sessions[client_ip].append(timestamp)

    # All anomaly detection functions as per your original code...
    def get_request_count(self, client_ip, within_seconds):
        now = time.time()
        requests = self.request_logs[client_ip]
        return sum(1 for req_time, _, _, _ in requests if now - req_time < within_seconds)

    def detect_rate_limit(self, client_ip):
        count_window = self.get_request_count(client_ip, self.window_seconds)
        return count_window > self.rate_limit

    def measure_session_duration(self, client_ip):
        if client_ip not in self.current_sessions or len(self.current_sessions[client_ip]) < 2:
            return 0
        timestamps = self.current_sessions[client_ip]
        return max(timestamps) - min(timestamps)

    def detect_spike_frequency(self, client_ip):
        requests = list(self.request_logs[client_ip])[-10:]
        if len(requests) < 5:
            return False
        timestamps = [req[0] for req in requests]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        spike_count = sum(1 for delta in intervals if delta < 0.5)
        return spike_count >= 3

    def detect_parallel_requests(self, client_ip):
        requests = list(self.request_logs[client_ip])[-10:]
        if len(requests) < 5:
            return False
        timestamps = [req[0] for req in requests]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        parallel_count = sum(1 for delta in intervals if delta < 0.2)
        return parallel_count >= 3

    def analyze_crawl_depth_and_linearity(self, client_ip):
        requests = list(self.request_logs[client_ip])[-20:]
        if len(requests) < 5:
            return False
        paths = [req[1] for req in requests]
        depths = [path.count('/') for path in paths]
        unique_paths = len(set(paths))
        total_paths = len(paths)
        linearity_ratio = unique_paths / total_paths
        low_linearity = linearity_ratio < 0.5
        increasing_depth = all(x <= y for x, y in zip(depths, depths[1:]))
        return low_linearity and increasing_depth

    def identify_non_human_delay_patterns(self, client_ip):
        requests = list(self.request_logs[client_ip])[-20:]
        if len(requests) < 5:
            return False
        timestamps = [req[0] for req in requests]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        if len(intervals) < 2:
            return False
        stddev = statistics.stdev(intervals)
        mean = statistics.mean(intervals)
        uniform_threshold = 0.1
        very_short_threshold = 0.5
        return stddev < uniform_threshold or mean < very_short_threshold

    def detect_form_submission_flood(self, client_ip):
        requests = list(self.request_logs[client_ip])[-20:]
        post_form_reqs = [req for req in requests if req[2].upper() == "POST" and req[3]]
        return len(post_form_reqs) > 5

    def profile_repetitive_access(self, client_ip):
        requests = list(self.request_logs[client_ip])[-20:]
        if len(requests) < 5:
            return False
        paths = [req[1] for req in requests]
        unique_paths = set(paths)
        return len(unique_paths) < len(paths) / 2

    def assign_behavioral_anomaly_score(self, client_ip):
        score = 0
        details = []
        if self.detect_rate_limit(client_ip):
            score += 2
            details.append("High request rate")
        duration = self.measure_session_duration(client_ip)
        if duration < 10 and self.detect_spike_frequency(client_ip):
            score += 2
            details.append("Short session with spike frequency")
        if self.detect_parallel_requests(client_ip):
            score += 2
            details.append("Rapid parallel requests")
        if self.analyze_crawl_depth_and_linearity(client_ip):
            score += 1
            details.append("Linear crawl pattern")
        if self.identify_non_human_delay_patterns(client_ip):
            score += 1
            details.append("Non-human delay pattern")
        if self.detect_form_submission_flood(client_ip):
            score += 2
            details.append("Form submission flood")
        if self.profile_repetitive_access(client_ip):
            score += 1
            details.append("Repetitive endpoint access")
        return score, details

    def log_session_request_patterns(self, client_ip):
        requests = list(self.request_logs[client_ip])
        count = len(requests)
        unique_paths = len(set(req[1] for req in requests))
        print(f"\nSession Summary for {client_ip}:")
        print(f"- Total requests: {count}")
        print(f"- Unique endpoints accessed: {unique_paths}\n")

    def process_traffic_instance(self, client_ip, path, method, timestamp, form_submission=False):
        self.log_request(client_ip, path, method, timestamp, form_submission)
        score, details = self.assign_behavioral_anomaly_score(client_ip)
        self.log_session_request_patterns(client_ip)
        print("Behavioral Anomaly Score:", score)
        if score >= self.anomaly_score_threshold:
            print("!!! Suspicious/Bot-like activity detected !!!")
        else:
            print("Activity appears normal.")
        if details:
            print("Anomaly details:", ", ".join(details))
        else:
            print("No anomalies detected.")

    def extract_request_info(self, raw_request):
        """
        Extract client_ip, method, path, and form_submission flag from raw HTTP request text.
        Assumptions for this demo:
        - IP provided in a header like X-Forwarded-For or appended in a comment line.
        - Method and path parsed from request line.
        - Form submission assumed True if method POST and Content-Type contains form data.
        """
        lines = raw_request.splitlines()
        method = None
        path = None
        content_type = ""
        client_ip = None
        form_submission = False

        # Extract request line: e.g. POST /api/search HTTP/1.1
        request_line_match = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d.\d", lines[0])
        if request_line_match:
            method = request_line_match.group(1)
            path = request_line_match.group(2)

        # Parse headers for Content-Type and IP info
        for line in lines[1:]:
            line = line.strip()
            if line.lower().startswith("content-type:"):
                content_type = line.partition(":")[2].strip().lower()
            elif line.lower().startswith("x-forwarded-for:"):
                client_ip = line.partition(":")[2].strip().split(",")[0]
            elif line.lower().startswith("client-ip:"):
                client_ip = line.partition(":")[2].strip()
            elif line.lower().startswith("x-real-ip:"):
                client_ip = line.partition(":")[2].strip()
            elif line.startswith("# client_ip:"):
                client_ip = line.partition(":")[2].strip()

        # Default client_ip to localhost if missing
        if not client_ip:
            client_ip = "127.0.0.1"

        # Assume form submission if POST and content-type is form data
        if method == "POST" and ("application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type):
            form_submission = True

        return client_ip, path, method, form_submission

def main():
    analyzer = TrafficAnalyzer()
    print("= Traffic Analyzer Demo =")
    print("Provide the path to a text file containing a raw HTTP request for analysis. Enter 'exit' to quit.")

    while True:
        file_path = input("Enter request file path: ").strip()
        if file_path.lower() == 'exit':
            break

        try:
            with open(file_path, 'r') as f:
                raw_request = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            continue

        client_ip, path, method, form_submission = analyzer.extract_request_info(raw_request)
        timestamp = time.time()

        print(f"\nExtracted info: IP={client_ip}, Path={path}, Method={method}, Form Submission={form_submission}")

        analyzer.process_traffic_instance(client_ip, path, method, timestamp, form_submission)
        print("-" * 80)

if __name__ == '__main__':
    main()
