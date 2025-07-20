# AI-Enhanced API Endpoint Discovery Script: Complete Documentation

The **Hybrid API Endpoint Discovery Script** is a robust and intelligent tool engineered for cybersecurity professionals, penetration testers, and security researchers. It innovatively combines traditional wordlist-based enumeration with advanced AI capabilities, powered by Google's Gemini API, to provide a comprehensive and adaptive approach to API reconnaissance.

Whether you're performing a black-box assessment, conducting a red team exercise, or augmenting your existing vulnerability discovery workflow, this tool offers a flexible, powerful, and insightful solution.

-----

## 📋 Table of Contents

1.  [🎯 Overview](https://www.google.com/search?q=%23overview)
2.  [🛠 Installation & Setup](https://www.google.com/search?q=%23installation--setup)
      * [Prerequisites](https://www.google.com/search?q=%23prerequisites)
      * [Google Gemini API Setup](https://www.google.com/search?q=%23google-gemini-api-setup)
3.  [🚀 Basic Usage](https://www.google.com/search?q=%23basic-usage)
      * [Quick Start Examples](https://www.google.com/search?q=%23quick-start-examples)
      * [Core Parameters (Non-AI)](https://www.google.com/search?q=%23core-parameters-non-ai)
4.  [🧠 AI Integration Guide](https://www.google.com/search?q=%23ai-integration-guide)
      * [Understanding AI Features](https://www.google.com/search?q=%23understanding-ai-features)
      * [AI Model Selection](https://www.google.com/search?q=%23ai-model-selection)
      * [Managing Gemini Rate Limits & Costs](https://www.google.com/search?q=%23managing-gemini-rate-limits--costs)
5.  [🔍 Security Testing Workflows](https://www.google.com/search?q=%23security-testing-workflows)
6.  [📊 Output Formats & Reporting](https://www.google.com/search?q=%23output-formats--reporting)
      * [Console Output](https://www.google.com/search?q=%23console-output)
      * [File Formats](https://www.google.com/search?q=%23file-formats)
      * [AI Summary Example](https://www.google.com/search?q=%23ai-summary-example)
7.  [🔧 Advanced Configuration](https://www.google.com/search?q=%23advanced-configuration)
8.  [🐛 Troubleshooting](https://www.google.com/search?q=%23troubleshooting)
9.  [✅ Best Practices](https://www.google.com/search?q=%23best-practices)
      * [Security Testing Best Practices](https://www.google.com/search?q=%23security-testing-best-practices)
      * [Performance Optimization](https://www.google.com/search?q=%23performance-optimization)
      * [Ethical and Legal Considerations](https://www.google.com/search?q=%23ethical-and-legal-considerations)
      * [Integration with Other Tools](https://www.google.com/search?q=%23integration-with-other-tools)
10. [📈 Advanced Use Cases](https://www.google.com/search?q=%23advanced-use-cases)
11. [🚀 Future Enhancements](https://www.google.com/search?q=%23future-enhancements)

-----

## 🎯 Overview

This script is a production-ready API endpoint discovery tool designed for cybersecurity professionals, penetration testers, and security researchers. It seamlessly combines traditional wordlist-based discovery with advanced AI capabilities powered by Google's Gemini API, moving beyond simple brute-force to intelligent and adaptive reconnaissance.

Whether you're performing a black-box assessment, conducting a red team exercise, or augmenting your existing vulnerability discovery workflow, this tool offers a flexible, powerful, and insightful solution.

**Key Features:**

  * **Hybrid Discovery:** Combines traditional wordlist-based enumeration with intelligent AI-powered path generation.
  * **AI-Enhanced Discovery:** Generate initial API paths or dynamically expand the search space based on discovered patterns using Google Gemini.
  * **Intelligent Response Analysis:** Leverage AI to analyze "interesting" HTTP responses for potential security implications, sensitive data, or unusual behaviors.
  * **Adaptive Scanning:** Automatically adjusts request delay upon encountering target API rate limits (HTTP 429).
  * **Flexible HTTP Methods:** Test endpoints with GET, POST, PUT, DELETE, PATCH, HEAD, and OPTIONS requests.
  * **Customization:** Supports custom HTTP headers (e.g., for authentication), JSON payloads, and proxy configurations.
  * **Concurrency Control:** Adjustable threading for balancing scan speed and stealth for both HTTP requests and Gemini API calls.
  * **Comprehensive Reporting:** Output scan results in human-readable text, structured JSON, or CSV formats, including AI-generated insights and summaries.
  * **Graceful Exit:** Handles `Ctrl+C` cleanly to preserve discovered data.

**What Makes It Different:**

  * **Context-Aware AI:** Generates paths based on the target domain and can dynamically adapt based on discovered endpoint patterns.
  * **Real-Time Security Analysis:** AI analyzes raw HTTP responses for nuanced vulnerabilities and sensitive data, providing qualitative insights beyond just status codes.
  * **Dynamic Augmentation:** Adapts the scanning strategy by learning from initial findings, suggesting more targeted and potentially vulnerable paths.
  * **Professional Reporting:** Generates executive-level summaries with technical details, making findings easier to digest and prioritize.

-----

## 🛠 Installation & Setup

### Prerequisites

This script requires **Python 3.7+**.

1.  **Verify Python Version:**

    ```bash
    python3 --version
    ```

2.  **Install Required Python Packages:**
    Open your terminal or command prompt and run:

    ```bash
    pip install requests urllib3 google-generativeai
    ```

    The script includes a check for `google-generativeai` and will prompt you if it's missing.

### Google Gemini API Setup

To utilize the powerful AI features, you'll need an API key for Google's Gemini.

1.  **Get a Free API Key:**

      * Visit [Google AI Studio](https://aistudio.google.com/).
      * Sign in with your Google account.
      * Click "Create API key" or navigate to "Get API key" in the left sidebar.
      * Copy the generated key.

2.  **Set Environment Variable (Recommended for Security):**
    Set your API key as an environment variable named `GEMINI_API_KEY`. This is the most secure method as it keeps your key out of your script and command history.

      * **Linux/macOS:**
        ```bash
        export GEMINI_API_KEY="your_api_key_here"
        # To make it permanent, add this line to your shell's profile file (e.g., ~/.bashrc, ~/.zshrc).
        ```
      * **Windows (Command Prompt):**
        ```cmd
        set GEMINI_API_KEY="your_api_key_here"
        # For permanent setting, search "Environment Variables" in Windows, then add a New User Variable.
        ```
      * **Windows (PowerShell):**
        ```powershell
        $env:GEMINI_API_KEY="your_api_key_here"
        # For permanent setting, add to your PowerShell profile.
        ```

3.  **Verify Installation:**
    Run the script with the `--help` flag to confirm all dependencies are met and the script is executable:

    ```bash
    python api_discovery.py --help
    ```

-----

## 🚀 Basic Usage

To run the script, you must provide a target base URL.

### Quick Start Examples

**1. Basic Scan (No AI):**

```bash
python api_discovery.py https://api.example.com
```

  * Uses the default SecLists wordlist.
  * Tests `GET` and `POST` methods.
  * Uses 10 concurrent threads with a 5-second timeout.
  * Provides basic output to the console.

**2. AI-Enhanced Basic Scan:**

```bash
python api_discovery.py https://api.example.com \
    --gemini-key YOUR_API_KEY \
    --ai-paths 50 \
    --ai-analysis
```

  * Adds 50 AI-generated paths to the wordlist.
  * AI analyzes interesting responses for security implications.
  * Provides enhanced security insights in the output.

**3. Comprehensive Scan with Full AI and JSON Report:**

```bash
python api_discovery.py https://api.example.com \
    --gemini-key YOUR_API_KEY \
    --ai-paths 100 \
    --ai-analysis \
    --ai-dynamic \
    --ai-summary \
    -o results.json --format json
```

  * Enables the full AI feature set: initial AI paths, AI response analysis, dynamic AI path generation, and AI report summary.
  * Outputs a detailed JSON report.

### Core Parameters (Non-AI)

| Parameter           | Description                                                                 | Example                                            |
| :------------------ | :-------------------------------------------------------------------------- | :------------------------------------------------- |
| `url` (positional)  | Target base URL (e.g., `https://api.example.com`)                           | `https://api.example.com`                          |
| `-w`, `--wordlist`  | Custom wordlist file (defaults to SecLists download if not provided)        | `-w custom_paths.txt`                              |
| `-t`, `--threads`   | Number of concurrent HTTP threads (default: 10, use 1 for stealth)          | `-t 20`                                            |
| `-T`, `--timeout`   | Request timeout in seconds (default: 5)                                     | `-T 10`                                            |
| `-d`, `--delay`     | Delay between requests in seconds (default: 0, automatically increases on 429) | `-d 0.5`                                           |
| `-m`, `--methods`   | HTTP methods to test (default: `GET POST`)                                  | `-m GET POST PUT DELETE`                           |
| `-H`, `--headers`   | Custom headers (e.g., `"Authorization: Bearer token"`)                      | `-H "Authorization: Bearer token"`                 |
| `-p`, `--payload`   | Custom JSON payload for POST/PUT/PATCH requests                             | `-p '{"username":"test","password":"pwd"}'`        |
| `-o`, `--output`    | Output file for results                                                     | `-o results.json`                                  |
| `-f`, `--format`    | Output format (choices: `text`, `json`, `csv`; default: `text`)             | `-f json`                                          |
| `-q`, `--quiet`     | Quiet mode (minimal console output)                                         | `-q`                                               |
| `--follow-redirects`| Follow HTTP redirects (flag)                                                | `--follow-redirects`                               |
| `--proxy`           | Proxy URL (e.g., `http://localhost:8080`)                                   | `--proxy http://localhost:8080`                    |
| `-v`, `--verbose`   | Verbose logging for debugging                                               | `-v`                                               |

-----

## 🧠 AI Integration Guide

The script's core differentiator is its intelligent AI integration with Google's Gemini API. To enable any AI feature, you **must provide a Gemini API key** via the `GEMINI_API_KEY` environment variable or the `--gemini-key` argument.

### Understanding AI Features

**1. AI Path Generation (`--ai-paths`)**

  * **What it does:** Generates a specified number of intelligent and contextually relevant API paths based on the target domain. This expands the discovery scope beyond generic wordlists.
  * **Argument:** `--ai-paths <int>` (Default: `0` - disabled)
  * **How it works:** Gemini takes your target's domain and generates common REST API patterns for resources like users, auth, products, etc. These paths are added to your primary wordlist, and duplicates are automatically removed.
  * **Example AI-generated paths:**
      * `/api/v1/users`
      * `/api/v2/auth/login`
      * `/admin/dashboard`
      * `/mobile/api/sync`
      * `/internal/health`

**2. AI Response Analysis (`--ai-analysis`)**

  * **What it does:** After an HTTP request, for every "interesting" response (status code not 404, or within the `interesting_codes` set), Gemini analyzes the response content for security implications.
  * **Argument:** `--ai-analysis` (flag)
  * **How it works:** The script sends the URL, method, status, content type, and a truncated snippet (first 500 characters) of the response body to Gemini. Gemini then provides an analysis including:
      * **Vulnerability detection:** Identifies potential security flaws (e.g., XSS, SQLi, sensitive data exposure).
      * **Severity assessment:** Assigns a severity (Low/Medium/High/Critical).
      * **Sensitive data identification:** Flags presence of PII, API keys, etc.
      * **Follow-up recommendations:** Suggests further testing steps (e.g., authentication needs, parameter fuzzing).

**3. Dynamic Path Augmentation (`--ai-dynamic`)**

  * **What it does:** Makes the scanning adaptive. After the initial scan pass, Gemini analyzes the patterns of *already discovered* endpoints and generates new, more targeted paths based on these findings.
  * **Argument:** `--ai-dynamic` (flag)
  * **How it works:**
      * The script first completes a full scan using the base wordlist and any `--ai-paths`.
      * It then compiles a list of patterns from all `found_endpoints`. If the list is too long for Gemini's context window, it intelligently summarizes the key themes of discovered paths for the prompt.
      * These patterns are fed to Gemini, which suggests related path variations or sub-paths (e.g., if `/api/users` was found, it might suggest `/api/users/{id}/profile`, `/api/users/admin`, or `/api/users/../`).
      * A second scan pass is then initiated specifically for these newly generated dynamic paths.

**4. AI Summarization in Reports (`--ai-summary`)**

  * **What it does:** Generates an executive-level summary of the scan results using Gemini, highlighting key findings, potential risks, and top priorities.
  * **Argument:** `--ai-summary` (flag)
  * **How it works:** After the scan is complete, the script sends a summary of the discovered endpoints to Gemini. If many endpoints are found, the script will intelligently summarize them before sending to optimize prompt length. Gemini synthesizes this information into an "Overview," lists "Potential Risks" with severity, and identifies "Top Priorities" for investigation. This summary is included in the console output and the final report.

### AI Model Selection

  * **Argument:** `--gemini-model <model_name>`
  * **Default:** `gemini-2.5-flash`
  * **Available Models:**
      * `gemini-2.5-flash`: Fast, highly cost-effective, and suitable for most discovery and basic analysis tasks.
      * `gemini-2.5-pro`: Offers higher quality reasoning and understanding, but typically has lower free-tier limits and higher costs. Use for more complex or nuanced analysis needs.

### Managing Gemini Rate Limits & Costs

Google's Gemini API has usage limits, especially in the free tier. The script includes features to help manage this.

  * **`--gemini-concurrency <int>`:**
      * **Purpose:** Limits the maximum number of simultaneous calls your script makes to the Gemini API. This directly helps you stay within Gemini's Requests Per Minute (RPM) limits. The script also includes an exponential backoff for Gemini API calls, retrying with increasing delays if rate limits or other transient errors are encountered.
      * **Default:** `5`
      * **Tuning:** Refer to Google's official [Gemini API rate limits documentation](https://ai.google.dev/gemini-api/docs/rate-limits) for up-to-date values. For example, if `gemini-2.5-flash` has a free tier limit of 10 RPM, setting `--gemini-concurrency 5` provides a safe buffer. Adjust this value downwards if you frequently hit `429 Too Many Requests` errors from Gemini.
  * **Free Tier Limits (Example for `gemini-2.5-flash` - *subject to change, always check Google's official documentation for current limits*):**
      * Requests per Minute (RPM): 10
      * Tokens per Minute (TPM): 250,000
      * Requests per Day (RPD): 250

-----

## 🔍 Security Testing Workflows

The flexibility and AI capabilities of this script make it adaptable to various security testing scenarios.

**Workflow 1: Initial Reconnaissance (Quick Discovery)**

```bash
# Phase 1: Quick discovery
python api_discovery.py https://target.com \
    --gemini-key $GEMINI_API_KEY \
    --ai-paths 25 \
    -t 5 -d 0.3 \
    -o initial_scan.json

# Phase 2: Analyze the 'initial_scan.json' report and plan follow-up.
```

  * Aims for a rapid initial understanding of the API surface.
  * Uses a small number of AI-generated paths to broaden the initial wordlist.
  * Moderate threading and delay to balance speed and stealth.

**Workflow 2: Authenticated Testing**

```bash
# With authentication
python api_discovery.py https://api.target.com \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
    -H "X-API-Key: abc123def456" \
    --gemini-key $GEMINI_API_KEY \
    --ai-analysis \
    --ai-dynamic \
    -m GET POST PUT DELETE \
    -o authenticated.json
```

  * Includes authentication headers to discover endpoints only accessible to authenticated users.
  * Enables AI analysis and dynamic path augmentation for deeper discovery within the authenticated context.
  * Tests common read/write HTTP methods.

**Workflow 3: Stealth Testing (Low and Slow)**

```bash
# Low and slow approach
python api_discovery.py https://target.com \
    -t 1 \
    -d 2.0 \
    --gemini-key $GEMINI_API_KEY \
    --ai-paths 10 \
    --quiet \
    -o stealth_results.txt
```

  * Single-threaded (`-t 1`) with a significant delay (`-d 2.0`) to minimize detection.
  * Uses a small set of AI-generated paths for targeted expansion without high volume.
  * Quiet mode (`--quiet`) for minimal console noise.

**Workflow 4: Comprehensive Assessment (Full Feature Scan)**

```bash
# Full feature scan
python api_discovery.py https://api.target.com \
    --gemini-key $GEMINI_API_KEY \
    --ai-paths 100 \
    --ai-analysis \
    --ai-dynamic \
    --ai-summary \
    -m GET POST PUT DELETE PATCH OPTIONS \
    --follow-redirects \
    -t 15 \
    -o comprehensive.json --format json
```

  * Activates all AI features for maximum discovery and analysis.
  * Tests all common HTTP methods and follows redirects for thoroughness.
  * Increased threading for performance, suitable for authorized, controlled environments.

**Workflow 5: Through Proxy (e.g., Burp Suite / OWASP ZAP)**

```bash
# Route through security proxy
python api_discovery.py https://target.com \
    --proxy http://127.0.0.1:8080 \
    --gemini-key YOUR_GEMINI_API_KEY \
    --ai-analysis \
    -H "User-Agent: Custom-Scanner/1.0" \
    -o proxy_scan.csv --format csv
```

  * Routes all HTTP traffic (not Gemini API calls) through a local proxy, allowing you to intercept, modify, and analyze requests/responses in tools like Burp Suite or OWASP ZAP.
  * Adds a custom User-Agent for better identification in proxy logs.

-----

## 📊 Output Formats & Reporting

The script provides flexible reporting options for various needs.

### Console Output

During the scan, real-time updates are displayed with color-coded results:

```
[*] Progress: 50.1% (750/1500) - Found: 15
[200] GET     https://api.example.com/users (1234 bytes) application/json
      AI Analysis: Vulnerability: Sensitive Data Exposure...
[401] POST    https://api.example.com/admin (89 bytes) application/json
[403] GET     https://api.example.com/internal (156 bytes) text/html
```

### File Formats

You can save the full report to a file using the `-o` argument and choose the format with `-f`.

**1. JSON Format (`--format json`)**

Ideal for technical analysis, scripting, and integration with other tools.

```json
{
  "scan_info": {
    "target": "https://api.example.com",
    "timestamp": "2025-01-20T15:30:45.123456",
    "total_found": 23,
    "total_requests": 1500,
    "ai_summary": "Overview: Discovered 23 endpoints across authentication, user management, and administrative functions..."
  },
  "endpoints": [
    {
      "method": "GET",
      "url": "https://api.example.com/users",
      "path": "/users",
      "status": 200,
      "length": 1234,
      "content_type": "application/json",
      "server": "nginx",
      "redirect_location": null,
      "ai_analysis": "- Vulnerability: None\n- Severity: Low\n- Explanation: Standard user list retrieval.\n- Suggestions: Check pagination and filtering."
    },
    {
      "method": "POST",
      "url": "https://api.example.com/admin",
      "path": "/admin",
      "status": 401,
      "length": 89,
      "content_type": "application/json",
      "server": "nginx",
      "redirect_location": null,
      "ai_analysis": "- Vulnerability: Authentication Bypass (Potential)\n- Severity: Medium\n- Explanation: Received 401, but response body suggests incomplete auth. Further testing needed.\n- Suggestions: Test with various authentication methods."
    }
  ]
}
```

**2. CSV Format (`--format csv`)**

Perfect for spreadsheet analysis, tracking, and basic data manipulation.

```csv
Status,Method,URL,Path,Content-Type,Content-Length,Server,Redirect-Location,AI-Analysis
200,GET,https://api.example.com/users,/users,application/json,1234,nginx,,"- Vulnerability: None\n- Severity: Low..."
401,POST,https://api.example.com/admin,/admin,application/json,89,nginx,,"- Vulnerability: Authentication Bypass (Potential)\n- Severity: Medium..."
403,GET,https://api.example.com/internal,/internal,text/html,156,nginx,,"- Vulnerability: None\n- Severity: Low\n- Explanation: Expected forbidden access.\n- Suggestions: None."
```

**3. Text Format (`--format text`)**

A human-readable detailed report, suitable for documentation and quick review.

```
API Endpoint Discovery Report
==================================================
Target: https://api.example.com
Total Requests: 1500
Endpoints Found: 23
Scan Date: 2025-01-20 15:30:45

[200] GET https://api.example.com/users
    Content-Type: application/json
    Content-Length: 1234 bytes
    Server: nginx
    AI Analysis:
    - Vulnerability: Sensitive Data Exposure
    - Severity: Medium
    - Explanation: Response contains unredacted email addresses.
    - Suggestions: Implement data filtering for public endpoints.

[401] POST https://api.example.com/admin
    Content-Type: application/json
    Content-Length: 89 bytes
    Server: nginx
    AI Analysis:
    - Vulnerability: Authentication Required
    - Severity: Low
    - Explanation: Standard 401 for unauthenticated access.
    - Suggestions: Test with valid authentication.

[403] GET https://api.example.com/internal
    Content-Type: text/html
    Content-Length: 156 bytes
    Server: nginx
    AI Analysis:
    - Vulnerability: None
    - Severity: Low
    - Explanation: Expected forbidden access to internal endpoint.
    - Suggestions: None.

======================================================================
AI-GENERATED SUMMARY & RECOMMENDATIONS
======================================================================
Overview: Discovered 23 endpoints across authentication, user management,
and administrative functions. The scan identified 3 high-risk findings
that require immediate attention.

Potential Risks:
- High: The /admin endpoint appears to allow unauthorized access, indicated
  by a 200 OK status code when it should be protected.
- Medium: The /users endpoint exposes PII (e.g., email addresses) without authentication,
  which is a sensitive data exposure.
- Low: Generic information disclosure in error messages (e.g., stack traces)
  for specific endpoints.

Top Priorities:
1. /admin (Status 200): This endpoint is a critical authentication bypass vulnerability.
   Investigate access controls and ensure it requires proper authorization.
2. /users/{id} (Status 200 with PII): Test for Insecure Direct Object Reference (IDOR)
   vulnerabilities by attempting to access other user's data.
3. /internal/config (Status 200): This potentially sensitive configuration endpoint
   is accessible. Verify access controls and ensure no sensitive data is exposed.
======================================================================
```

### AI Summary Example

The AI-generated summary, if enabled, provides an executive-level overview and prioritizes findings:

```
AI-GENERATED SUMMARY & RECOMMENDATIONS
======================================================================
Overview: Discovered 23 endpoints across authentication, user management,
and administrative functions. 3 high-risk findings require immediate attention.

Potential Risks:
- High: /admin endpoint allows unauthorized access (Status 200)
- Medium: /users endpoint exposes PII without authentication
- Low: Information disclosure in error messages

Top Priorities:
1. /admin - Critical authentication bypass vulnerability
2. /users/{id} - Test for IDOR vulnerabilities
3. /internal/config - Potential configuration exposure
======================================================================
```

-----

## 🔧 Advanced Configuration

### Custom Headers for Authentication

```bash
# Bearer token for API authentication
-H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

# Custom API key
-H "X-API-Key: your-api-key-here"

# Multiple headers can be provided
-H "Authorization: Bearer token" -H "X-Custom-Header: value"
```

### Custom Payloads for POST/PUT/PATCH

```bash
# Basic JSON payload for login/registration
--payload '{"username":"test","password":"test123"}'

# Example payload for testing injection or cross-site scripting
--payload '{"id":"1 OR 1=1","data":"<script>alert(1)</script>"}'
```

### Threading and Performance

  * **High-speed scanning (aggressive):** `-t 50 -d 0.1`
  * **Stealth mode (slow and quiet):** `-t 1 -d 2.0 --quiet`
  * **Balanced approach:** `-t 10 -d 0.5`

### Method Combinations

  * **Basic REST methods:** `-m GET POST`
  * **Comprehensive testing:** `-m GET POST PUT DELETE PATCH OPTIONS HEAD`
  * **Specific methods only (e.g., for testing write operations):** `-m POST PUT`

-----

## 🐛 Troubleshooting

### Common Issues and Solutions

**1. Gemini API Errors**

  * **Problem:** `Gemini API error: 429 Too Many Requests`
      * **Cause:** Hitting Gemini's rate limits.
      * **Solution:** Reduce the `--gemini-concurrency` value (e.g., `--gemini-concurrency 1`). Consider using the `gemini-2.5-flash` model, which often has higher free-tier limits.
  * **Problem:** `Failed to initialize Gemini: ...` or `Gemini API error: Invalid API key`
      * **Cause:** Incorrect, expired, or missing Gemini API key.
      * **Solution:** Double-check your `GEMINI_API_KEY` environment variable or the `--gemini-key` argument. Ensure it's active in Google AI Studio.

**2. Target API Rate Limiting**

  * **Problem:** Target returns `429 Too Many Requests` errors for HTTP requests.
      * **Cause:** The target API is blocking requests due to high volume from your scanner.
      * **Solution:** The script automatically handles this by increasing the internal `delay`. For persistent issues, manually increase the initial `-d` (delay) or decrease `-t` (threads).

**3. Connection Issues**

  * **Problem:** `requests.exceptions.Timeout` (connection timeouts)
      * **Cause:** Network latency, slow server, or insufficient timeout setting.
      * **Solution:** Increase the timeout (`-T 10` for 10 seconds). You might also need to reduce the number of threads (`-t 5`).
  * **Problem:** `requests.exceptions.ConnectionError`
      * **Cause:** Network connectivity issues, target server offline, or firewall blocking.
      * **Solution:** Verify network connection and target availability.

**4. Performance for Large Targets**

  * **Problem:** Scan takes too long.
      * **Solution:**
          * Use a smaller, more focused custom wordlist (`-w smaller_wordlist.txt`).
          * Limit the HTTP methods to test (`-m GET POST`).
          * If only AI-generated paths are desired, use `--ai-paths 50 -w /dev/null` (using `/dev/null` as a dummy wordlist, or an empty file).

**5. Memory Issues**

  * **Problem:** High memory usage with very large result sets.
      * **Solution:**
          * Use quiet mode and output directly to a file (`--quiet -o results.json`).
          * For extremely large scans, consider temporarily disabling dynamic AI augmentation (`--ai-dynamic`) as it can generate many paths.

### Debug Mode

  * **Enable verbose logging:** `-v`
  * **Example Debug Command:**
    ```bash
    python api_discovery.py https://target.com -v --gemini-key $GEMINI_API_KEY
    ```
    This will print detailed messages about script execution, HTTP requests, and Gemini API interactions to help diagnose issues.

-----

## ✅ Best Practices

### Security Testing Best Practices

1.  **Authorization Testing:**

      * **Test without authentication first:** `python api_discovery.py https://api.target.com`
      * **Then test with authentication:**
        `python api_discovery.py https://api.target.com -H "Authorization: Bearer valid_token"`
      * **Compare results:** Look for endpoints accessible without authentication that should be protected (authentication bypasses, sensitive data exposure).

2.  **Progressive Scanning:**

      * **Start small and focused:** Begin with fewer threads, a small number of AI paths, and perhaps only `GET` requests (`--ai-paths 10 -t 5`).
      * **Scale up based on target behavior:** If the target is stable, gradually increase threads and enable more advanced AI features (`--ai-paths 50 -t 15 --ai-dynamic`).

3.  **Documentation and Reporting:**

      * **Always save results:** Use the `-o` flag with a timestamped filename (e.g., `-o scan_$(date +%Y%m%d_%H%M%S).json`) to avoid overwriting previous scans.
      * **Utilize AI summaries:** `--ai-summary` provides a high-level overview for executive reports.
      * **Export to different formats:** Use `--format json` for technical analysis, `--format csv` for spreadsheet tracking, and `--format text` for general documentation.

### Performance Optimization

1.  **Target-Specific Tuning:**

      * **For small APIs (\< 100 endpoints):** `-t 5 --ai-paths 25 --ai-analysis --ai-dynamic` (can be more aggressive).
      * **For large APIs (\> 1000 endpoints):** `-t 20 --ai-paths 10 --ai-analysis` (may consider skipping `--ai-dynamic` for initial large scans to control overall request count).
      * **For rate-limited targets:** `-t 1 -d 1.0 --ai-paths 5` (prioritize stealth and minimal AI usage).

2.  **AI Usage Optimization:**

      * **Conservative AI usage (to stay within free tier):** `--ai-paths 10 --gemini-concurrency 1` (minimizes Gemini API calls).
      * **Aggressive AI usage (requires paid tier):** `--ai-paths 100 --ai-dynamic --gemini-concurrency 10` (leverages AI heavily, but increases cost and risk of hitting higher rate limits).

### Ethical and Legal Considerations

1.  **Authorization:**

      * **Always obtain explicit permission** from the asset owner before scanning any system.
      * **Document authorization** in your testing notes.
      * **Respect scope limitations** outlined in your engagement agreement.

2.  **Rate Limiting:**

      * Start with **conservative settings** and gradually increase.
      * **Monitor target response times** and server load.
      * **Back off immediately** if you detect any negative impact on the target system's performance or availability.

3.  **Data Handling:**

      * Ensure **secure storage of your Gemini API key** and any other sensitive credentials.
      * Exercise **careful handling of discovered sensitive data** (e.g., PII, internal configurations).
      * Adhere to relevant **data retention and privacy policies** (e.g., GDPR, CCPA).

### Integration with Other Tools

1.  **Burp Suite / OWASP ZAP Integration:**

      * Route traffic through your local proxy for manual inspection and further testing:
        `--proxy http://127.0.0.1:8080`
      * Export results to JSON for easy import into other tools.

2.  **Custom Wordlists:**

      * Tailor your wordlists for specific industry sectors or API types (e.g., `-w financial_api_paths.txt` for banking APIs, `-w healthcare_paths.txt` for healthcare APIs).

3.  **CI/CD Integration:**

      * Automate API discovery in your continuous integration/continuous deployment (CI/CD) pipeline for early detection of new or exposed endpoints.

    <!-- end list -->

    ```bash
    #!/bin/bash
    # Automated security scanning script for CI/CD

    export GEMINI_API_KEY="your_key" # Ensure key is securely managed in CI/CD environment

    python api_discovery.py https://staging-api.company.com \
        --ai-paths 25 \
        --ai-analysis \
        --quiet \
        -o staging_scan_$(date +%Y%m%d).json

    # Process results for a security gate
    # Example: Fail build if new critical endpoints or vulnerabilities are detected
    if grep -q '"severity": "Critical"' staging_scan_*.json; then
        echo "CRITICAL VULNERABILITY DETECTED - BUILD FAILED!"
        exit 1
    fi
    if grep -q '"status": 200' staging_scan_*.json && grep -q '"path": "/new_admin_api"' staging_scan_*.json; then
        echo "New /new_admin_api endpoint discovered - manual review required - BUILD FAILED!"
        exit 1
    fi
    echo "API Scan completed successfully."
    ```

-----

## 📈 Advanced Use Cases

**Use Case 1: Bug Bounty Hunting**

```bash
# Initial reconnaissance for a bug bounty target
python api_discovery.py https://api.target.com \
    --gemini-key $GEMINI_API_KEY \
    --ai-paths 50 \
    --ai-analysis \
    --ai-dynamic \
    -t 10 -d 0.5 \
    -o bounty_scan.json

# Focus on AI-flagged high-value findings from 'bounty_scan.json'.
# Manually test AI-flagged endpoints for exploitability.
# Document findings thoroughly, leveraging AI analysis as supporting evidence.
```

**Use Case 2: Red Team Assessment**

```bash
# Phase 1: Stealthy external reconnaissance
python api_discovery.py https://target.internal \
    -t 1 -d 3.0 \
    --gemini-key $GEMINI_API_KEY \
    --ai-paths 10 \
    --quiet \
    -o redteam_recon.txt

# Phase 2: Authenticated enumeration after initial access (e.g., with a compromised token)
python api_discovery.py https://target.internal \
    -H "Authorization: Bearer compromised_token" \
    --ai-analysis \
    --ai-dynamic \
    -o redteam_enum.json
```

**Use Case 3: API Security Assessment**

```bash
# Comprehensive security audit for a client API
python api_discovery.py https://client-api.com \
    --gemini-key $GEMINI_API_KEY \
    --ai-paths 100 \
    --ai-analysis \
    --ai-dynamic \
    --ai-summary \
    -m GET POST PUT DELETE PATCH \
    --follow-redirects \
    -t 15 \
    -o security_audit.json

# Generate executive summary for client reporting using the AI summary.
# Utilize the detailed JSON report for technical deep-dives and remediation recommendations.
```

-----

## 🚀 Future Enhancements

Based on professional feedback, here are some key areas targeted for future development to further enhance the script's capabilities and operational readiness:

  * **API Key Security:** Implementing support for encrypted API key storage or direct integration with dedicated secret management systems (e.g., HashiCorp Vault, cloud secret managers) to bolster credential security.
  * **Output Sanitization:** Adding configurable options to automatically redact sensitive data (e.g., PII, authentication tokens, session IDs) from output reports, ensuring responsible data handling and privacy.
  * **SSL/TLS Verification:** Providing options for custom certificate validation, crucial for operating within corporate environments that utilize internal Certificate Authorities (CAs).
  * **Rate Limiting Intelligence:** Enhancing the adaptive rate limiting to analyze server response patterns beyond just `429 Too Many Requests` codes, incorporating `Retry-After` headers, response time fluctuations, or subtle content changes that indicate server stress.
  * **Response Fingerprinting:** Developing capabilities to detect and adapt to specific API frameworks (e.g., Django REST Framework, FastAPI, Node.js Express), allowing for even more targeted AI prompts and default fuzzing patterns.
  * **Custom AI Prompts:** Empowering security professionals to customize or provide their own Gemini prompts for specific AI analysis tasks, enabling highly domain-specific insights and tailored vulnerability detection.
  * **Resume Capability:** Implementing the ability to save and resume interrupted scans from checkpoints, greatly improving operational resilience for large-scale and long-running assessments.
  * **Distributed Scanning:** Exploring the potential for multi-node or distributed scanning architectures to allow for horizontal scalability when assessing vast and complex API surfaces.
  * **Integration APIs:** Developing REST API endpoints for programmatic control of the scanning process and retrieval of results, facilitating seamless integration with broader security platforms, CI/CD pipelines, and GRC systems.

-----
