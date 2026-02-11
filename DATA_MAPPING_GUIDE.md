# Data Mapping Tab Guide

## Overview
The **Data Mapping Tab** (🗺️ icon) visualizes and maps all attack vectors from documented sites in the Hades-AI database.

## Features

### 1. **Attack Vector Overview**
- Real-time statistics on:
  - Total Security Patterns discovered
  - Total Threat Findings identified
  - Total Learned Exploits
  - Total CVEs catalogued
  - Documented sites analyzed

### 2. **Site Selection**
- Choose between:
  - **All Sites** - View aggregated data across all documented sites
  - **Specific Sites** - Drill down into attack vectors for individual targets

### 3. **Multiple View Modes**

#### Attack Vectors Overview
Shows a summary of all attack vectors with counts and relationships.

#### Threat Findings
Displays security threats organized by:
- Threat Type
- Severity (Critical, High, Medium, Low)
- Code Patterns
- Detected Context

#### Security Patterns
Lists identified security patterns with:
- Pattern Type
- Confidence Score
- Occurrence Count
- Example Signatures
- Countermeasures
- CWE IDs

#### Learned Exploits
Shows exploits discovered during reconnaissance:
- Exploit Type
- Source URL
- Success/Failure Ratio
- Code Snippet
- Description

#### CVE Mappings
Displays related CVEs with:
- CVE ID
- CVSS Score
- Summary
- Affected Products
- Mitigation Strategies
- References

#### Technique Coverage
Shows MITRE ATT&CK techniques identified:
- Technique Name
- Category
- Confidence Score
- Detection Rules
- Mitigations

#### Timeline Analysis
Temporal analysis showing:
- When attacks were discovered
- Pattern evolution over time
- Exploitation lag times
- Response timelines
- Campaign correlations

#### Risk Matrix
Visual representation of:
- Severity vs Threat Type
- Risk prioritization
- Impact assessment
- Resource allocation recommendations

## Usage Workflow

### 1. **Initial Assessment**
```
Start → Select "All Sites" → View "Attack Vectors Overview"
→ Review summary statistics
```

### 2. **Deep Dive Analysis**
```
Select Specific Site → Choose detailed view
→ Examine individual attack vectors
→ Cross-reference with CVEs/Techniques
```

### 3. **Export & Reporting**
```
Click "Export" → Choose JSON/CSV format
→ Generate detailed threat report
→ Share findings with team
```

### 4. **Risk Assessment**
```
Switch to "Risk Matrix" view
→ Identify high-priority threats
→ Plan remediation
→ Document findings
```

## Data Sources

The tab integrates data from multiple database tables:

- **security_patterns** - Detected code patterns and vulnerabilities
- **threat_findings** - Specific security threats
- **learned_exploits** - Successfully identified exploits
- **cves** - Known CVE database
- **techniques** - MITRE ATT&CK mappings
- **web_learnings** - Sites and knowledge discovered
- **attack_events** - Historical attack data

## Color Coding

**Severity Levels:**
- 🔴 **Critical** - Red (#ff0000)
- 🟠 **High** - Orange (#ff7700)
- 🟡 **Medium** - Yellow (#ffff00)
- 🟢 **Low** - Green (#00ff00)
- 🔵 **Info** - Cyan (#00ccff)

## Export Options

### JSON Export
Contains:
- Timestamp
- Target information
- Full summary statistics
- Top 10 patterns, threats, exploits, CVEs

```json
{
  "timestamp": "2024-02-11T10:30:00",
  "site": "target.com",
  "summary": {
    "total_patterns": 45,
    "total_threats": 23,
    "total_exploits": 12,
    "total_cves": 8
  },
  "vectors": {...}
}
```

### CSV Export
Tabular format suitable for:
- Spreadsheet analysis
- Team collaboration
- Management reporting
- Compliance documentation

## Key Metrics

### Confidence Score
- Range: 0% - 100%
- Indicates likelihood the pattern/technique is relevant
- Higher scores = more reliable findings

### CVSS Score
- Range: 0.0 - 10.0
- 9.0+ : Critical
- 7.0-8.9 : High
- 4.0-6.9 : Medium
- 0.1-3.9 : Low

### Success Rate
- Ratio of successful to failed exploits
- Used to prioritize attack vectors
- Tracks exploit reliability over time

## Tips & Best Practices

1. **Regular Updates**
   - Refresh data frequently to catch new vectors
   - Monitor for pattern changes

2. **Prioritization**
   - Focus on Critical/High severity threats first
   - Check CVSS scores for impact assessment

3. **Correlation**
   - Link threats to specific CVEs
   - Connect exploits to attack techniques

4. **Documentation**
   - Export reports for records
   - Track discovery timeline

5. **Team Collaboration**
   - Share mappings with security teams
   - Use for vulnerability management planning

## Troubleshooting

### No data showing?
- Ensure database has been populated (run reconnaissance)
- Check "All Sites" option
- Refresh the tab

### Missing vectors?
- Verify web_learning data is populated
- Check database integrity
- Run threat detection tools

### Export fails?
- Check file write permissions
- Ensure sufficient disk space
- Verify output format selection

## Integration with Other Tabs

The Data Mapping tab complements:
- **🛡️ Active Defense** - Use mapped vectors for defense rules
- **🔍 Threat Findings** - View detailed threat context
- **🧠 Web Knowledge** - Understand knowledge sources
- **💉 Request Injection** - Test identified attack vectors
- **⚔️ Active Exploit** - Execute exploits based on vectors
- **🔓 Auth Bypass** - Apply authentication attack patterns

## Example Workflow: Assessing a Target

1. Select target from site dropdown
2. Review Attack Vectors Overview
3. Switch to Threat Findings → identify severity breakdown
4. Check CVE Mappings → understand known vulnerabilities
5. Review Learned Exploits → identify proven attacks
6. Switch to Risk Matrix → prioritize response
7. Click "Generate Report" → share findings
8. Click "Export" → save for compliance
