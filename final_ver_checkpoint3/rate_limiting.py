import time
from collections import defaultdict, deque
import statistics
import re

class TrafficAnalyzer:
    def __init__(self, rate_limit=10, window_seconds=60, anomaly_score_threshold=5, max_history=10000):
        # Stores request data per IP: (timestamp, path, method, form_submission_flag)
        self.request_logs = defaultdict(lambda: deque(maxlen=max_history))
        self.rate_limit = rate_limit              # Max allowed requests within window
        self.window_seconds = window_seconds      # Time window for rate limiting
        self.anomaly_score_threshold = anomaly_score_threshold
        self.current_sessions = defaultdict(list) # Session timestamps per IP

    # ---------------- Core logging ----------------
    def log_request(self, client_ip, path, method, timestamp, form_submission=False):
        self.request_logs[client_ip].append((timestamp, path, method, form_submission))
        self.current_sessions[client_ip].append(timestamp)

    def process_traffic_instance(self, client_ip, path, method, timestamp, form_submission=False):
        self.log_request(client_ip, path, method, timestamp, form_submission)
        # This method is intentionally side-effect free beyond logging; scoring is pulled explicitly.

    # ---------------- Helpers ----------------
    def _recent_requests(self, client_ip, n=None):
        if n is None:
            return list(self.request_logs[client_ip])
        return list(self.request_logs[client_ip])[-int(max(0, n)):]

    def get_request_count(self, client_ip, within_seconds):
        now = time.time()
        requests = self.request_logs[client_ip]
        return sum(1 for req_time, _, _, _ in requests if now - req_time < within_seconds)

    def measure_session_duration(self, client_ip):
        if client_ip not in self.current_sessions or len(self.current_sessions[client_ip]) < 2:
            return 0.0
        timestamps = self.current_sessions[client_ip]
        return max(timestamps) - min(timestamps)

    # ---------------- Detections ----------------
    def detect_rate_limit(self, client_ip):
        count_window = self.get_request_count(client_ip, self.window_seconds)
        return count_window > self.rate_limit

    def detect_spike_frequency(self, client_ip):
        # Spike: many very short inter-arrival intervals in last 10 requests
        requests = self._recent_requests(client_ip, 10)
        if len(requests) < 5:
            return False
        timestamps = [req[0] for req in requests]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        spike_count = sum(1 for delta in intervals if delta < 0.5)
        return spike_count >= 3

    def detect_parallel_requests(self, client_ip):
        # Parallel: multiple intervals nearly simultaneous
        requests = self._recent_requests(client_ip, 10)
        if len(requests) < 5:
            return False
        timestamps = [req[0] for req in requests]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        parallel_count = sum(1 for delta in intervals if delta < 0.2)
        return parallel_count >= 3

    def analyze_crawl_depth_and_linearity(self, client_ip):
        # Linear crawl: low unique path ratio + increasing depth over last 20
        requests = self._recent_requests(client_ip, 20)
        if len(requests) < 5:
            return False
        paths = [req[1] for req in requests]
        depths = [path.count('/') for path in paths]
        unique_paths = len(set(paths))
        total_paths = len(paths)
        linearity_ratio = unique_paths / total_paths if total_paths else 1.0
        low_linearity = linearity_ratio < 0.5
        increasing_depth = all(x <= y for x, y in zip(depths, depths[1:]))
        return low_linearity and increasing_depth

    def identify_non_human_delay_patterns(self, client_ip):
        # Non-human: highly uniform or too-short mean intervals over last 20
        requests = self._recent_requests(client_ip, 20)
        if len(requests) < 5:
            return False
        timestamps = [req[0] for req in requests]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        if len(intervals) < 2:
            return False
        try:
            stddev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            stddev = 0.0
        mean = statistics.mean(intervals) if intervals else 0.0
        uniform_threshold = 0.1
        very_short_threshold = 0.5
        return stddev < uniform_threshold or mean < very_short_threshold

    def detect_form_submission_flood(self, client_ip):
        # Flood: >5 POST form submissions in last 20
        requests = self._recent_requests(client_ip, 20)
        post_form_reqs = [req for req in requests if req[2].upper() == "POST" and req[3]]
        return len(post_form_reqs) > 5

    def profile_repetitive_access(self, client_ip):
        # Repetitive: uniqueness below 50% in last 20
        requests = self._recent_requests(client_ip, 20)
        if len(requests) < 5:
            return False
        paths = [req[1] for req in requests]
        unique_paths = set(paths)
        return len(unique_paths) < len(paths) / 2.0

    # ---------------- Scoring ----------------
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

    # ---------------- CLI Demo (optional) ----------------
    def extract_request_info(self, raw_request):
        """
        Extract client_ip, path, method, form_submission flag from raw HTTP request text.
        - IP from X-Forwarded-For/X-Real-IP or '# client-ip:' comment line
        - Method+path from request line
        - Form true if POST with form Content-Type
        """
        lines = raw_request.splitlines()
        method, path, content_type, client_ip = None, None, "", None
        form_submission = False

        if lines:
            m = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d", lines[0])
            if m:
                method, path = m.group(1), m.group(2)

        for line in lines[1:]:
            s = line.strip()
            if s.lower().startswith("content-type:"):
                content_type = s.partition(":")[2].strip().lower()
            elif s.lower().startswith("x-forwarded-for:"):
                client_ip = s.partition(":")[2].strip().split(",")[0]
            elif s.lower().startswith("client-ip:"):
                client_ip = s.partition(":")[2].strip()
            elif s.lower().startswith("x-real-ip:"):
                client_ip = s.partition(":")[2].strip()
            elif s.startswith("# client-ip:"):
                client_ip = s.partition(":")[2].strip()

        if not client_ip:
            client_ip = "127.0.0.1"

        if method == "POST" and (
            "application/x-www-form-urlencoded" in content_type or
            "multipart/form-data" in content_type
        ):
            form_submission = True

        return client_ip, path or "/", method or "GET", form_submission

def main():
    analyzer = TrafficAnalyzer()
    print("= Traffic Analyzer Demo =")
    print("Provide the path to a text file containing a raw HTTP request for analysis. Enter 'exit' to quit.")
    while True:
        file_path = input("Enter request file path: ").strip()
        if file_path.lower() == 'exit':
            break
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_request = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            continue

        client_ip, path, method, form_submission = analyzer.extract_request_info(raw_request)
        timestamp = time.time()
        print(f"\nExtracted info: IP={client_ip}, Path={path}, Method={method}, Form Submission={form_submission}")

        analyzer.process_traffic_instance(client_ip, path, method, timestamp, form_submission)
        score, details = analyzer.assign_behavioral_anomaly_score(client_ip)
        print(f"Behavioral Anomaly Score: {score}")
        if score >= analyzer.anomaly_score_threshold:
            print("!!! Suspicious/Bot-like activity detected !!!")
        else:
            print("Activity appears normal.")
        if details:
            print("Anomaly details:", ", ".join(details))
        else:
            print("No anomalies detected.")
        print("-" * 80)

if __name__ == "__main__":
    main()
