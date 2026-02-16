# Live Target Simulations Guide

Enhanced pentesting simulations that can pull real data from websites and targets.

## Installation

```bash
pip install -r requirements_simulations.txt
```

## Features

### 1. **Scenario-Based Training** (Original)
- Pre-built vulnerable app scenarios
- Realistic simulated responses
- AI coaching feedback
- Progressive difficulty levels

### 2. **Live Target Scanning** (NEW)
Fetch real data from live websites:

| Command | What It Does |
|---------|-------------|
| `curl <url>` or `http <url>` | Fetch page content and headers |
| `nmap <url>` or `scan <url>` | Analyze security headers |
| `form <url>` or `fuzzing <url>` | Extract all forms and input fields |
| `endpoint <url>` or `api <url>` | Extract API endpoints and scripts |

## Usage Modes

### Mode 1: Simulated Scenarios (Default)
1. Select a scenario from the list (e.g., "E-Commerce Login Bypass")
2. Execute pentesting commands
3. Get AI coaching feedback
4. Progress through difficulty levels

### Mode 2: Live Target Data
1. Check "Use Live Target Data" checkbox
2. Enter target URL (e.g., `http://example.com`)
3. Execute reconnaissance commands
4. Analyze real data extracted from the target

## Example Workflows

### Example 1: Analyze a Real Website
```
Target: http://example.com
Commands:
  1. curl http://example.com
  2. nmap example.com
  3. form example.com
  4. endpoint example.com
```

This will:
- Fetch the homepage content
- Check security headers (CSP, HSTS, X-Frame-Options)
- Extract all web forms and their input fields
- Discover API endpoints and external scripts

### Example 2: Scenario Training
```
Scenario: E-Commerce Login Bypass
Commands:
  1. curl http://target/login
  2. sqlmap --dbs
  3. union select ...
```

AI will provide coaching after each command.

## Data Extraction Details

### Security Headers Analysis
Returns information about:
- CSP (Content-Security-Policy)
- HSTS (HTTP Strict-Transport-Security)
- X-Frame-Options
- Server version
- All response headers

### Form Extraction
Discovers:
- Form action URLs
- HTTP method (GET/POST)
- Input field names and types
- Pre-filled values
- Text areas and select dropdowns

### Endpoint Discovery
Finds:
- External script sources
- Internal links
- Potential API routes
- Static asset paths

### Dynamic Response Generation
When commands are executed against live targets, the system:
1. Fetches real data from the target
2. Parses HTML/JSON responses
3. Simulates realistic tool output
4. Highlights security misconfigurations

## Important Notes

### Safety & Legal
- **Always get written permission** before scanning any target
- Only scan systems you own or are explicitly authorized to test
- Respect rate limits and system resources
- Follow your local laws and regulations

### Network Considerations
- Live scanning requires internet connectivity
- Requests include proper User-Agent headers
- SSL/TLS verification can be disabled for testing (use caution)
- Automatic retry logic for resilience
- 10-second timeout per request (configurable)

### Best Practices
1. **Start with your own test server** to practice safely
2. **Use example.com** for harmless reconnaissance practice
3. **Document all findings** in the coaching panel
4. **Combine techniques** - don't just run one command
5. **Practice both modes** - scenarios for learning, live for skills

## Advanced Configuration

### Custom Target URL Validation
The system automatically validates and normalizes URLs:
```
Input: example.com → Converted to http://example.com
Input: https://secure.example.com → Keeps HTTPS
```

### Retry Logic
Automatic retries on:
- Connection timeouts
- HTTP 5xx errors
- Network interruptions

### Threading
Live scanning runs in background threads to prevent UI freezing.

## Troubleshooting

### "Error fetching [URL]"
- Check if URL is accessible
- Verify internet connection
- Try with a known working site like example.com

### Forms not appearing
- Target page may be dynamically generated (JavaScript)
- Try looking at page source with `curl`
- Some sites require specific User-Agent or cookies

### Slow responses
- Network latency (try a closer target)
- Target server is slow
- Large pages take longer to parse
- Adjust timeout in WebTargetScanner if needed

### SSL/TLS errors
- Many educational targets use self-signed certs
- System allows unverified HTTPS for testing
- Production systems should verify certificates

## Command Reference

### Reconnaissance Commands
```
curl http://example.com          # Get HTTP response
curl -I http://example.com       # Get headers only
http http://example.com          # Alternative HTTP client
wget http://example.com          # Download content
```

### Security Scanning
```
nmap example.com                 # Port/header analysis
scan example.com                 # Quick security scan
header example.com               # Response headers
ssl example.com                  # SSL/TLS analysis
```

### Form & Input Enumeration
```
form example.com                 # Extract all forms
fuzzing example.com              # Prepare fuzz inputs
input example.com                # Find input fields
query example.com                # Query parameters
```

### Endpoint Discovery
```
endpoint example.com             # Find API endpoints
api example.com                  # API discovery
link example.com                 # Find all links
script example.com               # Find external scripts
```

## Integration with AI Coaching

After fetching live data, the system can:
- Suggest vulnerabilities to test
- Recommend exploitation techniques
- Explain security headers
- Identify unusual configurations
- Guide you through exploitation chains

## FAQ

**Q: Can I use this on any website?**
A: Only with explicit permission. Many sites have terms against automated scanning.

**Q: Does it do port scanning?**
A: The `nmap` command simulates port scanning by analyzing HTTP headers. True port scanning would require additional tools.

**Q: Can I test for SQL injection on live targets?**
A: The coaching system guides you through injection techniques, but actual exploitation should only be done on authorized targets.

**Q: What about CAPTCHA and authentication?**
A: Basic unauthenticated reconnaissance is supported. For authenticated areas, you may need to manually handle login.

**Q: How much traffic does this generate?**
A: Minimal - each command makes 1-2 HTTP requests. Very lightweight compared to real pentest tools.

## Future Enhancements

Planned additions:
- Cookie/session management
- Custom headers and authentication
- JavaScript rendering for dynamic sites
- Proxy integration
- Request/response manipulation
- Automated vulnerability detection
- Report generation
