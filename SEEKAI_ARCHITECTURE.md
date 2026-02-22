# Seeker + AI Integration - Architecture Diagram

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           HADES AI - EXPLOIT SEEK TAB
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │  User Interface (PyQt6)                                                 │  │
│  │                                                                         │  │
│  │  [Target URL Input]  [⚡ SEEK]  [🤖 TEST]  [🔗 UNIFIED] ← NEW BUTTON   │  │
│  │                                                                         │  │
│  │  Status Bar: "✅ UNIFIED ANALYSIS COMPLETE: 45 exploits + 12 AI..."    │  │
│  │                                                                         │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │ Results Table (Correlated View)                                  │  │  │
│  │  │ ┌──────────────┬──────────┬──────────┬──────────┬─────────────┐  │  │  │
│  │  │ │ Type         │ Severity │ AI Score │ Combined │ Correlation│  │  │  │
│  │  │ ├──────────────┼──────────┼──────────┼──────────┼─────────────┤  │  │  │
│  │  │ │ SQL Inject   │ Critical │ 92%      │ 0.94     │ ✓ Match     │  │  │  │
│  │  │ │ Auth Bypass  │ High     │ 85%      │ 0.88     │ ✓ Match     │  │  │  │
│  │  │ │ XSS Stored   │ Medium   │ 68%      │ 0.71     │ ✗ No match  │  │  │  │
│  │  │ └──────────────┴──────────┴──────────┴──────────┴─────────────┘  │  │  │
│  │  │                                                                    │  │  │
│  │  │ Detailed Report showing correlations, reasoning, etc.           │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                         │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                    ▲                                           │
│                          UnifiedIntegrationWorker                              │
│                            (QThread)                                           │
│                                    │                                           │
└────────────────────────────────────┼───────────────────────────────────────────┘
                                     │
                                     ▼
           ┌─────────────────────────────────────────────────────┐
           │         SeekAIIntegration (Pipeline Coordinator)    │
           │                                                     │
           │  analyze_and_score(target_url, callback)          │
           │                                                     │
           │  1. Run AI Analysis                               │
           │  2. Run Exploit Seeking                           │
           │  3. Score exploits vs context                     │
           │  4. Correlate findings                            │
           │  5. Generate reports                              │
           │                                                     │
           └─────────────────────────────────────────────────────┘
                    ▲                              ▲
                    │                              │
        ┌───────────┴─────────┐      ┌────────────┴──────────────┐
        │                     │      │                           │
        ▼                     ▼      ▼                           ▼
    ┌────────────┐      ┌──────────────┐      ┌─────────────┐  ┌──────────────┐
    │ AI Testing │      │ Exploit      │      │  Scoring    │  │ Correlation  │
    │            │      │  Seeking     │      │  Engine     │  │  Engine      │
    │ Detects:   │      │              │      │             │  │              │
    │ - Techs    │      │ Finds:       │      │ Calculates: │  │ Links:       │
    │ - Weak pts │      │ - Exploits   │      │ - AI score  │  │ - Exploits ↔ │
    │ - Vulns    │      │ - Payloads   │      │ - Relevance │  │   Vulns      │
    │ - Headers  │      │ - Impact     │      │ - Priority  │  │ - Strength   │
    └────────────┘      └──────────────┘      └─────────────┘  └──────────────┘
         │                   │                       │               │
         │ VulnerabilityCtx  │ List[Dict]           │ ScoredExploit  │
         └───────────────────┴───────────────────────┴────────────────┘
                                      │
                                      ▼
                            ┌──────────────────┐
                            │ UnifiedResult    │
                            │                  │
                            │ - seek_findings  │
                            │ - ai_findings    │
                            │ - correlations   │
                            │ - context        │
                            │ - summary        │
                            └──────────────────┘
```

---

## Data Flow Diagram

```
TARGET URL: "https://dvwa.local"
│
└─→ UnifiedIntegrationWorker
    │
    ├─────────────────────────────────────┐
    │                                     │
    ▼ (PARALLEL)                         ▼ (PARALLEL)
    
AI Analysis                          Exploit Seeking
├─ Fingerprint                       ├─ Query databases
├─ Tech detection                    ├─ Parse results
├─ Vuln scanning                     ├─ Extract payloads
├─ Header analysis                   └─ Build list
│
└─→ VulnerabilityContext             └─→ List[Exploit]
    {                                     [
      detected_technologies: [...],       {
      weak_points: [...],                   type: "sql_injection",
      likely_vulnerabilities: [...]         payload: "...",
    }                                       ...
                                         },
                                         ...
                                       ]
│
└─→ Scoring Engine
    │
    ├─ For each exploit:
    │  ├─ Check against detected_vulnerabilities
    │  ├─ Match against weak_points
    │  ├─ Calculate relevance score (0-1)
    │  └─ Create ScoredExploit
    │
    └─→ List[ScoredExploit]
        [
          {
            exploit_id: "exploit_1",
            exploit_type: "sql_injection",
            ai_relevance_score: 0.95,
            ai_success_probability: 0.92,
            ai_reasoning: "Matches detected SQL Injection...",
            matched_vulnerabilities: ["SQL Injection"],
            execution_priority: 1,
          },
          ...
        ]

│
└─→ Correlation Engine
    │
    ├─ For each AI finding:
    │  └─ Find matching exploits
    │
    └─→ List[Correlation]
        [
          {
            ai_finding_id: "ai_1",
            ai_title: "SQL Injection Vulnerability",
            applicable_exploits: ["exploit_1", "exploit_5"],
            correlation_strength: "direct",
          },
          ...
        ]

│
└─→ UnifiedResult
    │
    ├─ seek_findings: List[ScoredExploit]      (45 items)
    ├─ ai_findings: List[Dict]                 (12 items)
    ├─ correlations: List[Dict]                (8 items)
    ├─ context: VulnerabilityContext           (target intel)
    └─ summary: str                            (executive summary)

│
└─→ Display to User
    ├─ Table with rankings
    ├─ Color-coded correlations
    ├─ Detailed report
    └─ Export options (JSON, text)
```

---

## Scoring Algorithm Visualization

```
Raw Exploit from Database
    │
    ├─ Confidence: 0.65 (from source)
    │
    └─→ SCORING PIPELINE
        │
        ├─ Base AI Score: 0.5
        │
        ├─ Check: Does exploit type match detected vulnerabilities?
        │  └─ SQL Injection exploit vs detected "SQL Injection"?
        │     └─ YES: +0.2 → Score = 0.7
        │
        ├─ Check: Does exploit match weak points?
        │  └─ SQL Injection vs "No prepared statements"?
        │     └─ YES: +0.15 → Score = 0.85
        │
        ├─ Check: Compatible with detected tech?
        │  └─ SQL exploit vs "MySQL detected"?
        │     └─ YES: +0.1 → Score = 0.95
        │
        ├─ Check: Can bypass detected defenses?
        │  └─ SQL bypass vs "No WAF"?
        │     └─ YES: +0.1 → Score = 1.0 (capped)
        │
        └─→ FINAL: AI Relevance Score = 0.95
        
        Combined Score = (0.65 × 0.4) + (0.95 × 0.6)
                       = 0.26 + 0.57
                       = 0.83
        
        Execution Priority = 1 (highest)
```

---

## Result Correlation Visualization

```
AI VULNERABILITIES                    EXPLOITS
────────────────────                 ────────

SQL Injection                ┐
(Severity: Critical)        │        SQL Union Select
(Confidence: 95%)           ├──────→ (Score: 0.94) ✓
                            │        
                            │        SQL Time-based Blind
                            ├──────→ (Score: 0.89) ✓
                            │
                            │        SQL Error-based
                            └──────→ (Score: 0.86) ✓


Weak CSRF Protection       ┐
(Severity: High)           │        CSRF Token Bypass
(Confidence: 88%)          ├──────→ (Score: 0.81) ✓
                           │
                           │        Auth Bypass
                           └──────→ (Score: 0.76) ✓


Missing Auth Headers       ┐
(Severity: Medium)         │        Missing Authentication
(Confidence: 72%)          └──────→ (Score: 0.68) ✓


Reflected XSS             ┐
(Severity: Medium)        │        XSS Reflected
(Confidence: 68%)         ├──────→ (Score: 0.71) ✓
                          │
                          │        XSS Stored
                          └──────→ (Score: 0.64) ✓
```

Legend:
- ✓ = Correlated (appears in report, highlighted green)
- ✗ = Not correlated (lower priority, highlighted red)

---

## Class Hierarchy

```
SeekAIIntegration (Main Coordinator)
│
├─ Attributes:
│  ├─ ai_tester: AIVulnerabilityTester
│  ├─ exploit_seeker: ExploitSeeker
│  ├─ unified_seeker: UnifiedExploitKnowledge
│  ├─ current_context: VulnerabilityContext
│  ├─ current_result: UnifiedResult
│  └─ vulnerability_patterns: Dict[str, List[str]]
│
├─ Methods:
│  ├─ analyze_and_score() → UnifiedResult
│  ├─ _run_ai_analysis() → (List[Dict], VulnerabilityContext)
│  ├─ _run_exploit_seeking() → List[Dict]
│  ├─ _score_exploits() → List[ScoredExploit]
│  ├─ _calculate_ai_relevance() → (float, str, List[str])
│  ├─ _correlate_findings() → List[Dict]
│  ├─ get_ranked_exploits() → List[ScoredExploit]
│  ├─ get_exploit_by_priority() → ScoredExploit
│  ├─ get_findings_for_vulnerability() → List[ScoredExploit]
│  └─ export_results() → str


ScoredExploit (Dataclass)
├─ exploit_id: str
├─ exploit_type: str
├─ description: str
├─ payload: str
├─ severity: str
├─ confidence: float (0-1)
├─ ai_relevance_score: float (0-1)
├─ ai_success_probability: float (0-1)
├─ ai_reasoning: str
├─ source: str
├─ impact: str
├─ remediation: str
├─ execution_priority: int
├─ matched_vulnerabilities: List[str]
└─ combined_score: property (0-1)


VulnerabilityContext (Dataclass)
├─ target_url: str
├─ analysis_time: float
├─ detected_technologies: List[str]
├─ detected_frameworks: List[str]
├─ security_headers: Dict[str, str]
├─ weak_points: List[str]
├─ likely_vulnerabilities: List[str]
├─ defense_mechanisms: List[str]
└─ ai_observations: str


UnifiedResult (Dataclass)
├─ target: str
├─ timestamp: float
├─ seek_findings: List[ScoredExploit]
├─ ai_findings: List[Dict]
├─ context: VulnerabilityContext
├─ correlations: List[Dict]
├─ summary: str
└─ total_findings: property (int)


UnifiedIntegrationWorker (QThread)
├─ Signals:
│  ├─ finished: pyqtSignal(dict)
│  ├─ progress: pyqtSignal(str)
│  └─ error: pyqtSignal(str)
│
└─ Methods:
   ├─ run()
   └─ _exploit_to_dict()
```

---

## Integration Points

```
┌─ HadesAI.py
│  └─ Creates ExploitSeekTab
│     └─ Which creates SeekAIIntegration
│        ├─ Uses AIVulnerabilityTester
│        ├─ Uses ExploitSeeker
│        └─ Uses UnifiedExploitKnowledge (optional)
│
├─ Command-line scripts
│  └─ Import SeekAIIntegration directly
│     └─ Configure with available components
│
└─ Third-party tools
   └─ Accept UnifiedResult for further processing
```

---

## Performance Characteristics

```
Sequential Execution:
┌─────────────────┐
│  AI Analysis    │  30-60s
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Exploit Seek   │  10-30s
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Scoring        │  <5s
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Correlation    │  <5s
└─────────────────┘
         │
Total: 40-90 seconds


Parallel Execution (What Actually Happens):
┌─────────────────┐
│  AI Analysis    │  30-60s   ──┐
└─────────────────┘            │ Results combined
┌─────────────────┐            │
│  Exploit Seek   │  10-30s   ──┤
└─────────────────┘            │
                               │
                        ▼
                    ┌──────────────┐
                    │ Scoring      │  <5s
                    │ Correlation  │  <5s
                    └──────────────┘
         │
Total: 40-90 seconds (parallel components save ~10-30s)
```

---

## Message Flow During Analysis

```
User clicks "🔗 UNIFIED ANALYSIS"
        │
        ▼
"📊 Running AI vulnerability analysis..."
        │
        ├─ [AI Processing...]
        │
        ▼
"📊 AI found 12 vulnerabilities"
        │
        ├─ [Exploit Seeking in parallel...]
        │
        ▼
"🔍 Using unified exploit knowledge..."
        │
        ├─ [Searching...]
        │
        ▼
"🔍 Unified seeker found 45 exploits"
        │
        ├─ [Collecting results...]
        │
        ▼
"⚡ Scoring exploits against target context..."
        │
        ├─ • Checked sql_injection vs SQL Injection (95% match)
        ├─ • Checked auth_bypass vs Auth Bypass (88% match)
        └─ • ...
        │
        ▼
"🔗 Correlating findings across systems..."
        │
        ├─ • Linked 45 exploits to 12 vulnerabilities
        └─ • Found 8 strong correlations
        │
        ▼
"✅ Analysis complete: 45 exploits + 12 AI findings + 8 correlations"
        │
        ▼
[Display Results Table & Report]
```

---

This architecture provides **intelligent, correlated vulnerability intelligence** by combining the strengths of both AI analysis and exploit discovery into a single unified pipeline.
