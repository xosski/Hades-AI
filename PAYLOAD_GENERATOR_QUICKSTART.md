# Payload Generator - Quick Start

## What is It?
A tool that automatically generates attack payloads based on the file you upload. Upload a JavaScript file, get XSS payloads. Upload a SQL file, get SQL injection payloads. Simple!

## How to Use (30 seconds)

1. **Launch HadesAI** and find the **📦 Payload Gen** tab
2. **Click "Browse..."** and select any file
3. **Wait 1 second** - the tool detects the type and generates payloads
4. **Copy payloads** from the table and test them
5. **Done!** Use the payloads in your security testing

## Supported File Types

| Type | File Extensions | # Payloads | Use Case |
|------|-----------------|-----------|----------|
| JavaScript | .js, .jsx, .ts | 7 | XSS testing in web apps |
| SQL | .sql | 6 | SQL injection testing |
| XML | .xml, .svg | 4 | XXE and XML injection |
| JSON | .json | 5 | NoSQL injection, prototype pollution |
| HTML | .html, .htm | 6 | DOM XSS and iframe injection |
| PHP | .php | 5 | Code injection in PHP |
| Python | .py | 5 | Code injection in Python |
| CSV | .csv | 5 | Formula injection in Excel |
| And more... | Various | 4-7 | PDF, images, office, archives, binary |

## 3 Common Workflows

### Workflow 1: Quick Test
```
1. Open Payload Gen tab
2. Upload your file
3. Copy a payload
4. Paste in target form
5. See if it works
```

### Workflow 2: Batch Testing
```
1. Upload multiple files
2. Export payloads to file
3. Use with your favorite fuzzer/scanner
4. Analyze results
```

### Workflow 3: Integration Testing
```
1. Generate payloads here
2. Craft requests in "Request Injection" tab
3. Execute in "Active Exploit" tab
4. Document findings in "Threat Findings" tab
```

## Key Features

✅ **Auto-Detection** - Detects file type automatically
✅ **Copy-Paste Ready** - Click once to copy payload
✅ **Export** - Save all payloads as TXT or JSON
✅ **Override** - Want different payloads? Override the detected type
✅ **Non-Blocking** - File analysis happens in background
✅ **Safe** - Payloads are templates, not executed

## Common Questions

**Q: Can I use these payloads on any system?**
A: No! Only use on systems you own or have permission to test. These are for authorized security testing only.

**Q: What if the type is detected wrong?**
A: Use the "Override Type" dropdown to manually select the correct type.

**Q: Can I create custom payloads?**
A: Not yet, but you can copy and modify existing ones.

**Q: How many payloads do I get?**
A: Usually 4-7 per file type, depending on the category.

**Q: Can I test all payloads at once?**
A: Export to file and use with your fuzzer tool (wfuzz, Burp, etc.)

## Payload Examples

### JavaScript
```
'; alert('XSS'); //
<img src=x onerror='alert(1)'>
```

### SQL
```
' OR '1'='1' --
admin'--
```

### XML
```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
```

### JSON
```
{"__proto__": {"admin": true}}
```

## Tips

💡 **Tip 1**: Upload files related to your target technology stack
💡 **Tip 2**: Override type to test multiple payload categories
💡 **Tip 3**: Export payloads for batch testing
💡 **Tip 4**: Combine with Request Injection tab for manual testing
💡 **Tip 5**: Use exported payloads with external security tools

## Keyboard Shortcuts

- **Browse**: Click "Browse..." button
- **Copy**: Select payload, click "Copy Selected Payload"
- **Export**: Click "Export All Payloads"
- **Clear**: Click "Clear" to reset

## Next Steps

1. **Read Full Docs**: Check `PAYLOAD_GENERATOR_README.md`
2. **See Examples**: Check `PAYLOAD_GENERATOR_EXAMPLES.md`
3. **Learn Integration**: Explore Request Injection and Active Exploit tabs
4. **Test**: Try with sample files to understand how it works

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Tab not visible | Ensure `payload_generator_gui.py` is in same folder as `HadesAI.py` |
| No payloads generated | Try a different file type, or manually override the type |
| Export fails | Check write permissions in target folder |
| File won't load | Ensure file is not corrupted and you have read permissions |

## Remember

⚠️ Use responsibly!
- Only test systems you have permission to test
- Comply with applicable laws
- Always get written authorization
- Follow responsible disclosure practices

---

**Ready to get started?** Open the 📦 Payload Gen tab and upload a file!
