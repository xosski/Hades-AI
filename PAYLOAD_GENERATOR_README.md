# Payload Generator Tab

## Overview
The **Payload Generator** tab is a powerful heuristic-based payload generation tool that automatically creates attack payloads based on the file type of uploaded files. It intelligently detects file types and generates context-relevant payloads for testing and analysis.

## Features

### 1. **Intelligent File Type Detection**
- Detects file types by:
  - File extension analysis
  - Binary signature verification
  - MIME type detection
- Supported file types:
  - JavaScript/TypeScript
  - SQL
  - XML/SVG/XSL
  - JSON
  - HTML
  - PHP
  - Python
  - CSV
  - PDF
  - Images
  - Office documents (DOCX, XLSX, PPTX, etc.)
  - Archives (ZIP, TAR, 7Z, etc.)
  - Binary executables (EXE, DLL, SO, etc.)

### 2. **Heuristic Payload Generation**
- Automatically generates relevant payloads for detected file types
- Payloads include:
  - **JavaScript**: XSS vectors, template injection, function calls
  - **SQL**: SQL injection variants, NoSQL bypasses, time-based attacks
  - **XML**: XXE injection, DTD attacks, XML bomb
  - **JSON**: Prototype pollution, type juggling, NoSQL injection
  - **HTML**: DOM-based XSS, iframe injection, event handlers
  - **PHP**: Code injection, eval/system calls, file inclusion
  - **Python**: RCE via eval/exec, pickle injection, subprocess
  - **CSV**: Formula injection, Excel/Calc injection
  - **PDF**: JavaScript embedded, XFA forms, launch actions
  - **Archives**: Path traversal, symlink attacks, decompression bombs
  - **Binary**: Buffer overflow, ROP chains, shellcode injection

### 3. **Interactive UI**
- **File Selection**: Browse and select any file for analysis
- **Type Override**: Manually override detected file type to generate payloads for different categories
- **Live Preview**: View generated payloads in a sortable table
- **Payload Details**: See detailed information about each payload
- **Copy to Clipboard**: Easily copy individual payloads for testing
- **Export Options**: Save payloads as TXT or JSON format

## Usage

### Basic Workflow
1. **Open the Payload Generator Tab**
   - Click on the "📦 Payload Gen" tab in the main HadesAI window

2. **Select a File**
   - Click "Browse..." to select a file
   - The tool automatically analyzes and detects its type

3. **View Generated Payloads**
   - Payloads appear in the table
   - Detected file type and count displayed
   - Select any payload to see details

4. **Use the Payloads**
   - Copy individual payloads for testing
   - Export all payloads for batch testing
   - Override type to test different payload categories

### File Type Override
If the detection is incorrect or you want payloads for a different type:
1. Open the "Payload Customization" section
2. Select a different type from "Override Type" dropdown
3. Click "Generate Payloads"
4. New payloads will be generated for the selected type

### Export Options
**TXT Format**: One payload per line, human-readable
```
Payloads for: /path/to/file.js
Type: javascript
==========
1. '; alert('XSS'); //
2. "; alert('XSS'); //
3. <script>alert('XSS')</script>
...
```

**JSON Format**: Structured format for automation
```json
{
  "file": "/path/to/file.js",
  "file_type": "javascript",
  "payloads": [
    "'; alert('XSS'); //",
    "...more payloads..."
  ]
}
```

## Payload Categories

### XSS & Injection Payloads
- Designed for web application testing
- Target common injection points
- Include both DOM-based and stored variants

### Authentication Bypass
- SQL injection for login bypass
- NoSQL bypass techniques
- Default credentials (covered in Auth Bypass tab)

### Code Execution
- PHP system() calls
- Python eval/exec injection
- Command execution vectors

### XXE & SSRF
- XML external entity injection
- Server-side request forgery
- Archive manipulation

### Formula Injection
- CSV formula injection
- Excel/LibreOffice formula execution
- Potential RCE through office apps

## Integration with Other Tools

### With Request Injection Tab
Export payloads and manually craft requests using the Injection tab

### With Active Exploit Tab
Use generated payloads to test exploits

### With Code Analysis Tab
Analyze code that might contain vulnerabilities matching these payloads

## Performance Notes
- File analysis is performed in background thread
- Large files (>100MB) may take longer to analyze
- Payload generation is instant for all file types

## Limitations
- Payloads are templates; actual effectiveness depends on:
  - Target vulnerability
  - Input validation
  - WAF/IDS filters
  - Application architecture

- Some payloads may require modification for specific contexts
- Binary analysis is limited to known patterns

## Examples

### Example 1: Analyzing JavaScript File
```
File: app.js
Detected Type: JavaScript
Payloads Generated: 7

Payloads include XSS vectors suitable for JavaScript contexts
```

### Example 2: Analyzing SQL File
```
File: query.sql
Detected Type: SQL
Payloads Generated: 6

Payloads include SQL injection variants and time-based attacks
```

### Example 3: Analyzing HTML File
```
File: form.html
Detected Type: HTML
Payloads Generated: 6

Payloads include DOM XSS, iframe injection, event handlers
```

## Security Considerations

⚠️ **IMPORTANT**: These payloads are for authorized security testing only.
- Only use on systems you have permission to test
- Comply with applicable laws and regulations
- Do not use for malicious purposes
- Always obtain written permission before testing

## Future Enhancements

Planned features:
- [ ] Payload encoding/obfuscation options
- [ ] WAF bypass techniques
- [ ] Custom payload creation
- [ ] Batch file analysis
- [ ] Payload effectiveness scoring
- [ ] Integration with Burp Suite
- [ ] Custom payload rules

## Troubleshooting

**Issue**: File type detected incorrectly
- **Solution**: Use the "Override Type" dropdown to manually select the correct type

**Issue**: No payloads generated
- **Solution**: Ensure file is not empty or corrupted. Try overriding the file type.

**Issue**: Export fails
- **Solution**: Ensure write permissions in target directory. Try a different location.

## Support

For issues, feature requests, or feedback:
- Check the main HadesAI README.md
- Review the code in payload_generator_gui.py
- Test with sample files to understand behavior
