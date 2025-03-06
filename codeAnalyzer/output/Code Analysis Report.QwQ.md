# Program Analysis Report: Threat Intelligence Scanning Tool

## **Program Overview**

This Python-based tool is designed for automated threat intelligence analysis using the VirusTotal API. It processes a list of inputs (IP addresses, URLs, or file hashes) from an `input.txt` file and performs asynchronous scans to check their reputation and malicious activity status via VirusTotal. The program emphasizes efficiency through parallel processing and robust error handling.

---

## **Core Objectives**

1. **Input Processing**:

   - Read input queries from a text file (`input.txt`).
   - Classify inputs into three categories using regex patterns:
     - IP addresses (IPv4)
     - URLs
     - File hashes (MD5, SHA-1, SHA-256).

2. **Asynchronous Scanning**:

   - Leverage the VirusTotal API to scan each category concurrently via three parallel tasks (`ipScan`, `urlScan`, and `fileScan`).
   - Optimize performance by handling multiple requests simultaneously using asyncio.

3. **Output & Reporting**:
   - Display scan results (e.g., detection statistics from antivirus engines) for each input.
   - Handle errors gracefully, such as invalid inputs or API key issues.

---

## **Key Components & Workflow**

### 1. **`main.py`: Entry Point**

- **Initialization**:
  - Validates the presence of `input.txt`. Exits with an error if missing.
  - Checks for a valid VirusTotal API key (placeholder in code; user must provide their own).
- **Input Categorization**:
  - Uses regex patterns to split inputs into three lists: `ips`, `urls`, and `file_hashes`.
- **Asynchronous Execution**:
  - Launches three parallel tasks via `asyncio.gather()`:
    ```python
    await asyncio.gather(
        ipScan(client, ips),
        urlScan(client, urls),
        fileScan(client, file_hashes)
    )
    ```
  - The `vt-py` library (`vt` module) is used to interact with the VirusTotal API.

### 2. **`utils.py`: Scanning Logic**

- Contains three core asynchronous functions:
  - **`ipScan(client, ips)`**: Queries VirusTotal for IP address reports and prints findings (e.g., number of malicious URLs detected).
  - **`urlScan(client, urls)`**: Checks URL reputation. Implements retries if a URL is marked as "pending" in initial scans.
  - **`fileScan(client, hashes)`**: Analyzes file hashes to retrieve antivirus detection statistics (harmless/malicious/suspicious counts).
- **Error Handling**: Uses `try/except` blocks to catch API rate limits or invalid inputs.

### 3. **`requirements.txt`: Dependency Management**

- Ensures consistent environments by pinning specific versions of critical libraries:
  - **aiohttp==3.8.1**: Enables asynchronous HTTP requests for concurrent API calls.
  - **vt-py==0.14.0**: Official VirusTotal Python client for API interactions.
  - **asyncio==3.4.3**: Manages event loops and coroutines for parallelism.

---

## **Technical Highlights**

- **Asynchronous Design**:  
  The program uses `async/await` syntax to process multiple scans concurrently, reducing overall execution time compared to synchronous approaches.
- **Input Validation**:
  - Regex patterns ensure inputs are correctly categorized (e.g., `[0-9]+(?:\.[0-9]+){3}` for IPs).
  - Validates the API key format and checks for missing dependencies.
- **Retry Mechanism**:  
  The `urlScan` function retries scans if a URL is initially unscanned ("pending" status), improving reliability.

---

## **Usage Requirements**

1. **Prerequisites**:
   - A valid VirusTotal API key (replace the placeholder in `main.py`).
   - An `input.txt` file containing one query per line (IPs, URLs, or hashes).
2. **Execution**:  
   Run `python main.py`, which will output scan results directly to the console.

---

## **Potential Improvements**

- **Output Formatting**: Add logging to a file instead of stdout for better record-keeping.
- **Rate Limit Handling**: Implement backoff strategies for API rate limits (currently only basic error catching).
- **Input Expansion**: Support additional input types like domain names or email addresses.

---

## **Conclusion**

This tool streamlines threat intelligence analysis by automating VirusTotal scans across multiple categories of inputs. Its asynchronous architecture ensures efficient processing, while robust validation and error handling make it reliable for security teams analyzing large datasets.
