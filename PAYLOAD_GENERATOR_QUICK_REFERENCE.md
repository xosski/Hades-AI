# Payload Generator - Quick Reference Card

## 🎯 At a Glance

| Feature | Action | Result |
|---------|--------|--------|
| **View Raw Payload** | Select payload → Raw Payload tab | See full payload clearly |
| **View All Payloads** | Generate → All Payloads tab | See numbered list |
| **View Info** | Generate → Info tab | See metadata/stats |
| **Copy One** | Select payload → 📋 Copy Selected | Clipboard ready |
| **Copy All** | No selection → 📋 Copy All | All payloads in clipboard |
| **Export** | 💾 Export All → Choose format | Save file (TXT/JSON/CSV) |
| **Show Raw** | Select payload → 📄 Show Raw | Display in raw viewer |
| **Clear** | 🗑️ Clear | Reset everything |

## 📂 Three Tabs

### Raw Payload Tab
```
Shows: One selected payload
Size: Large, easy to read
Use: Examining single payloads
```

### All Payloads Tab
```
Shows: Every payload numbered
Format: 1. payload
        2. payload
        ...
Use: Overview and reference
```

### Info Tab
```
Shows: File type, count, metadata
Format: FILE TYPE: javascript
        Total Payloads: 7
        ...
Use: Understanding generation
```

## 🔘 Button Meanings

| Button | Action | Result |
|--------|--------|--------|
| 📋 Copy Selected | Click after selecting payload | Single payload → clipboard |
| 📋 Copy All | Click anytime | All payloads → clipboard (newline-sep) |
| 💾 Export All | Click to save | File dialog opens |
| 📄 Show Raw | Click to display | Shows in Raw Payload tab |
| 🗑️ Clear | Click to reset | All data cleared |

## 📥 Export Formats

### TXT (Human-Readable)
```
Choose when: You want to read it
File looks: Professional with boxes and lines
Best for: Reports, documentation, reading
```

### JSON (Structured Data)
```
Choose when: You need to process it
File looks: {"metadata": {...}, "payloads": [...]}
Best for: Scripts, automation, parsing
```

### CSV (Spreadsheet)
```
Choose when: You want to use it in Excel/Sheets
File looks: Number,Type,Payload
Best for: Analysis, tracking, spreadsheets
```

## 🚀 5-Minute Workflow

```
1. UPLOAD FILE
   Click "Browse..." → Select any file → Auto-analyze

2. VIEW PAYLOADS
   Click "All Payloads" tab → See all numbered

3. SELECT ONE
   Click payload in table → Raw Payload tab shows it

4. COPY & TEST
   Click "📋 Copy Selected" → Paste into tool

5. DONE
   Test the payload, repeat for others
```

## 📋 Copy/Export Differences

| Task | Use | How |
|------|-----|-----|
| Copy single payload | Copy Selected | Exact text, one payload |
| Copy all at once | Copy All | All separated by newlines |
| Save for later | Export → TXT | Professional file, formatted |
| Use in script | Export → JSON | Includes metadata |
| Use in spreadsheet | Export → CSV | Columns: Number, Type, Payload |

## ⌨️ Quick Actions

```
1. Select payload in table (click row)
2. OPTION A: Copy
   → Click "📋 Copy Selected"
   → Paste into tool
   
2. OPTION B: View Large
   → Click "📄 Show Raw"
   → View in Raw Payload tab
   
2. OPTION C: Export
   → Click "💾 Export All"
   → Choose TXT/JSON/CSV
   → Save file
```

## 🎯 Common Tasks

### "I want to test one payload"
1. Select in table
2. Click "📋 Copy Selected"
3. Paste into test tool

### "I want to test all payloads"
1. Click "💾 Export All"
2. Choose TXT or CSV
3. Use file with fuzzer/scanner

### "I want to see a payload clearly"
1. Select in table
2. Click "📄 Show Raw"
3. View in Raw Payload tab

### "I want to share the payloads"
1. Click "💾 Export All"
2. Choose TXT for readability
3. Share the file

### "I want to automate testing"
1. Click "💾 Export All"
2. Choose JSON
3. Parse in your script

## 📊 Export Output Examples

### TXT Result
```
╔════════════════════════════════╗
║ PAYLOAD EXPORT - JAVASCRIPT    ║
╚════════════════════════════════╝
Source File: app.js
...
PAYLOAD #1
────────────────────────────────
'; alert('XSS'); //
────────────────────────────────
```

### JSON Result
```json
{
  "metadata": {
    "source_file": "app.js",
    "file_type": "javascript",
    "payload_count": 7,
    "generated_at": "2026-02-01T12:30:45"
  },
  "payloads": ["..."]
}
```

### CSV Result
```csv
Payload Number,Payload Type,Payload
1,javascript,'; alert('XSS'); //
2,javascript,"; alert('XSS'); //
```

## 🔍 Tab Quick Guide

### When to use Raw Payload Tab
- ✅ Examining a single payload
- ✅ Copying large/complex payloads
- ✅ Seeing exact text without truncation

### When to use All Payloads Tab
- ✅ Getting overview of all options
- ✅ Finding a specific payload
- ✅ Seeing payload count
- ✅ Copying all at once

### When to use Info Tab
- ✅ Understanding file type detected
- ✅ Seeing metadata
- ✅ Understanding generation stats
- ✅ Verifying payload count

## 💾 File Type Support

```
JAVASCRIPT: 7 payloads
SQL: 6 payloads
XML: 4 payloads
JSON: 5 payloads
HTML: 6 payloads
PHP: 5 payloads
PYTHON: 5 payloads
CSV: 5 payloads
...and more (14+ types)
```

## ✅ Verification Checklist

After exporting, verify:
- [ ] File created in correct location
- [ ] File contains correct number of payloads
- [ ] Payloads are readable/valid format
- [ ] Metadata (JSON) is present (if JSON export)
- [ ] Columns are present (if CSV export)

## 🎓 Pro Tips

**Tip 1**: Use Copy All for fuzzing
```
→ Click Copy All
→ Paste into fuzzer list
→ Run batch test
```

**Tip 2**: Use JSON for scripts
```
→ Export as JSON
→ Parse with json.load()
→ Iterate through payloads
```

**Tip 3**: Use TXT for reports
```
→ Export as TXT
→ Include in security report
→ Document test performed
```

**Tip 4**: Use CSV for analysis
```
→ Export as CSV
→ Open in Excel/Sheets
→ Add success/failure column
→ Track results
```

## 🔒 Remember

- ✅ Payloads are templates
- ✅ Nothing executes automatically
- ✅ Safe to copy and view
- ✅ No network operations
- ✅ Use responsibly and legally

## 📞 Need Help?

| Question | Answer |
|----------|--------|
| Where's the payload? | Check All Payloads tab |
| How to copy one? | Select + Copy Selected |
| How to save all? | Click Export All |
| What format to use? | TXT=read, JSON=script, CSV=sheets |
| Tab won't switch? | Click tab name at top |
| Button not working? | Select a payload first |

## 🚀 Success Indicators

✅ File uploaded successfully (label shows filename)
✅ Type detected (shows in dropdown)
✅ Payloads generated (shows in table)
✅ Tab viewer works (three tabs visible)
✅ Copy works (clipboard gets text)
✅ Export works (file created)

---

## One-Liner Cheat Sheet

| Need | Do This |
|------|---------|
| Single payload | Select → Copy Selected |
| All payloads | Copy All |
| Big view | Select → Show Raw |
| Save & share | Export All → TXT |
| Use in code | Export All → JSON |
| Use in Excel | Export All → CSV |
| See metadata | Click Info tab |
| See all | Click All Payloads tab |
| Start over | Click Clear |

---

**That's it!** You're ready to use the Payload Generator. Questions? Check the documentation files.
