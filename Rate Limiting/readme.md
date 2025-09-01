# Traffic Analyzer

A Python-based **HTTP traffic anomaly detection tool** that monitors request patterns, detects suspicious or bot-like behavior, and flags potential automated scraping or abusive activity.

---

## Key Features

- **Rate Limiting Detection**: Flags clients that exceed request thresholds within a time window.  
- **Session Analysis**: Measures session duration and tracks abnormal patterns.  
- **Spike Frequency Detection**: Identifies sudden bursts of requests in short intervals.  
- **Parallel Request Detection**: Detects rapid consecutive requests with very small gaps.  
- **Crawl Depth & Linearity Check**: Analyzes if paths follow a systematic crawler-like pattern.  
- **Non-Human Delay Detection**: Recognizes uniform or too-fast request intervals.  
- **Form Submission Flooding**: Detects excessive automated form submissions.  
- **Repetitive Endpoint Access**: Flags abnormal repetition of the same paths.  
- **Behavioral Anomaly Scoring**: Assigns a weighted score to each client and reports detailed anomalies.  
- **Raw HTTP Request Parsing**: Extracts IP, method, path, and form submission info from raw HTTP request files.  

---

## Workflow

1. **Input**: The script reads raw HTTP requests from text files.  
2. **Parsing**: Extracts client IP, HTTP method, path, and detects if it's a form submission.  
3. **Logging**: Stores request details per client IP.  
4. **Analysis**: Runs multiple anomaly detection modules on the logged requests.  
5. **Scoring**: Assigns an anomaly score with explanations of suspicious patterns.  
6. **Output**: Prints session summary, anomaly score, and whether activity is normal or suspicious.  

---

## Sample Input

Example raw HTTP request (`request.txt`):

```http
POST /api/search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 192.168.1.25

```
## Sample Output
After running the analyzer and providing the above file path:
```bash
= Traffic Analyzer Demo =
Provide the path to a text file containing a raw HTTP request for analysis. Enter 'exit' to quit.

Enter request file path: request.txt

Extracted info: IP=192.168.1.25, Path=/api/search, Method=POST, Form Submission=True

Session Summary for 192.168.1.25:
- Total requests: 1
- Unique endpoints accessed: 1

Behavioral Anomaly Score: 0
Activity appears normal.
No anomalies detected.
--------------------------------------------------------------------------------
```
If suspicious activity is detected:
```bash
Behavioral Anomaly Score: 6
!!! Suspicious/Bot-like activity detected !!!
Anomaly details: High request rate, Rapid parallel requests, Repetitive endpoint access
--------------------------------------------------------------------------------
```

## How to Run

1. Save the script as `traffic_analyzer.py`.  
2. Prepare raw HTTP request files (e.g., `request.txt`).  
3. Run the script:  
```bash
python traffic_analyzer.py
```
4. Enter the file path when prompted
5. Type 'exit' to quit



Example raw HTTP request (`request.txt`):

