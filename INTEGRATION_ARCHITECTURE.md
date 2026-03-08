# Payload-Exploit Integration Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           HadesAI Application                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌──────────────────────────────┐    ┌──────────────────────────────┐   │
│  │   Payload Generator Tab      │    │  Exploit Generator Tab       │   │
│  ├──────────────────────────────┤    ├──────────────────────────────┤   │
│  │                              │    │                              │   │
│  │ 1. Select File              │    │ 1. Select File               │   │
│  │ 2. Analyze File Type        │    │ 2. Analyze File              │   │
│  │ 3. Generate Payloads        │    │ 3. Detect Arch/Vulns         │   │
│  │ 4. Display Results          │    │ 4. Generate Exploit Code     │   │
│  │                              │    │ 5. Display Results           │   │
│  │ [AUTO INTEGRATION]           │    │ [AUTO INTEGRATION]           │   │
│  │ 5. Save to Database          │    │ 5. Create Workflow           │   │
│  │    (PayloadProfile)          │    │    (Link with Payloads)      │   │
│  │                              │    │ 6. Export Workflow           │   │
│  └──────────┬───────────────────┘    └────────────┬─────────────────┘   │
│             │                                      │                      │
│             │ PayloadProfile                       │ ExploitContext      │
│             │ - file_type                          │ - file_path         │
│             │ - payloads[]                         │ - vulnerabilities[] │
│             │ - categories[]                       │ - patterns[]        │
│             │ - profile_id                         │ - architecture      │
│             │                                      │ - context_id        │
│             └──────────────┬───────────────────────┘                     │
│                            │                                             │
│            ┌───────────────▼───────────────┐                             │
│            │  PayloadExploitLinker         │                             │
│            ├───────────────────────────────┤                             │
│            │ - create_workflow()           │                             │
│            │ - link_payload_to_exploit()   │                             │
│            │ - update_exploit_code()       │                             │
│            │ - export_workflow()           │                             │
│            │ - get_compatible_payloads()   │                             │
│            └───────────────┬───────────────┘                             │
│                            │                                             │
│            ┌───────────────▼────────────────────┐                        │
│            │  Linked Pair (pair_id)             │                        │
│            ├────────────────────────────────────┤                        │
│            │ - profile_id (from Payload Gen)    │                        │
│            │ - context_id (from Exploit Gen)    │                        │
│            │ - exploit_code (generated code)    │                        │
│            │ - payloads_used[]                  │                        │
│            │ - status (pending/generated)       │                        │
│            │ - created_at (timestamp)           │                        │
│            └───────────────┬────────────────────┘                        │
│                            │                                             │
│        ┌───────────────────▼───────────────────┐                         │
│        │   payload_exploit_integration.db      │                         │
│        ├───────────────────────────────────────┤                         │
│        │ TABLES:                               │                         │
│        │ - payload_profiles                    │                         │
│        │ - exploit_contexts                    │                         │
│        │ - linked_pairs                        │                         │
│        │ - execution_results                   │                         │
│        └───────────────────────────────────────┘                         │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

### Payload Generation Flow

```
User selects file
        |
        v
[Payload Generator Tab]
        |
        +---> PayloadGenerator.detect_file_type()
        |        |
        |        v
        |     File Type: "python", "javascript", "sql", etc.
        |
        +---> PayloadGenerator.generate_payloads()
        |        |
        |        v
        |     List of payloads for detected type
        |
        v
[_on_generation_complete()]
        |
        +---> Display payloads in UI
        |
        +---> [NEW] Create PayloadProfile
        |     - file_type
        |     - payloads
        |     - file_path, file_name, file_size
        |     - categories
        |     - generated_at
        |
        +---> [NEW] Call integration_linker.db.save_payload_profile()
        |     |
        |     v
        |  [SQLite Database]
        |  INSERT INTO payload_profiles
        |     |
        |     v
        |  profile_id = "prf_1704067200"
        |
        v
    [Workflow ready for linking]
```

### Exploit Generation Flow

```
User selects file
        |
        v
[Exploit Generator Tab]
        |
        +---> FileAnalyzer.analyze_file()
        |        |
        |        +---> _detect_file_type()
        |        +---> _detect_architecture()
        |        +---> _extract_strings()
        |        +---> _detect_suspicious_patterns()
        |        +---> _identify_vulnerabilities()
        |        v
        |     FileAnalysis object with all details
        |
        +---> [UI displays analysis]
        |
        +---> _ai_generate() -> Generate exploit code
        |
        v
[_on_exploit_generated()]
        |
        +---> Display exploit code in UI
        |
        +---> Store in database
        |
        +---> [NEW] Call _create_workflow()
        |     |
        |     +---> Create ExploitContext from FileAnalysis
        |     |     - file_path
        |     |     - file_type
        |     |     - architecture
        |     |     - suspicious_patterns
        |     |     - vulnerabilities
        |     |     - payloads (empty initially)
        |     |
        |     +---> Create PayloadProfile (empty for now)
        |     |
        |     +---> Call integration_linker.create_workflow()
        |     |     |
        |     |     +---> Save PayloadProfile to DB
        |     |     |        |
        |     |     |        v
        |     |     |     profile_id = "prf_1704067200"
        |     |     |
        |     |     +---> Save ExploitContext to DB
        |     |     |        |
        |     |     |        v
        |     |     |     context_id = "ctx_1704067200"
        |     |     |
        |     |     +---> Link them: link_payload_to_exploit()
        |     |     |        |
        |     |     |        v
        |     |     |     pair_id = "pair_1704067200"
        |     |     |
        |     |     +---> Save exploit code
        |     |            |
        |     |            v
        |     |         UPDATE linked_pairs SET exploit_code = ...
        |     |
        |     +---> Display notification with pair_id
        |
        v
    [Complete workflow available for export]
```

### Export Flow

```
User clicks "Export Workflow"
        |
        v
[export_workflow()]
        |
        +---> User selects output folder
        |
        +---> integration_linker.export_workflow_with_payloads()
        |     |
        |     +---> Get complete workflow from DB
        |     |     - payload_profile
        |     |     - exploit_context
        |     |     - exploit_code
        |     |     - payloads_used
        |     |
        |     +---> Create output directory
        |     |
        |     +---> Write exploit_{pair_id}.py
        |     |     (exploit code)
        |     |
        |     +---> Write payloads_{pair_id}.md
        |     |     (payload documentation)
        |     |
        |     +---> Write workflow_{pair_id}.json
        |     |     (complete workflow data)
        |
        v
    [Workflow exported successfully]
```

## Database Schema

```
payload_profiles
┌─────────────────────┬──────────┬─────────────────────┐
│ profile_id (PK)     │ prf_1234 │ prf_5678            │
├─────────────────────┼──────────┼─────────────────────┤
│ file_type           │ python   │ javascript          │
│ file_path           │ /f.py    │ /f.js               │
│ payloads_json       │ [...]    │ [...]               │
│ created_at          │ 2024-01  │ 2024-01             │
└─────────────────────┴──────────┴─────────────────────┘

exploit_contexts
┌──────────────────────┬──────────┬─────────────────────┐
│ context_id (PK)      │ ctx_1234 │ ctx_5678            │
├──────────────────────┼──────────┼─────────────────────┤
│ file_path            │ /f.exe   │ /lib.so             │
│ architecture         │ x86      │ x64                 │
│ vulnerabilities_json │ [...]    │ [...]               │
│ created_at           │ 2024-01  │ 2024-01             │
└──────────────────────┴──────────┴─────────────────────┘

linked_pairs
┌───────────────────┬──────────┬─────────────────────┐
│ pair_id (PK)      │ pair_123 │ pair_456            │
├───────────────────┼──────────┼─────────────────────┤
│ profile_id (FK)   │ prf_1234 │ prf_5678            │
│ context_id (FK)   │ ctx_1234 │ ctx_5678            │
│ exploit_code      │ [code]   │ [code]              │
│ payloads_used_json│ [...]    │ [...]               │
│ status            │ generated│ pending             │
│ created_at        │ 2024-01  │ 2024-01             │
└───────────────────┴──────────┴─────────────────────┘

execution_results
┌──────────────────┬──────────┬─────────────────────┐
│ result_id (PK)   │ res_1234 │ res_5678            │
├──────────────────┼──────────┼─────────────────────┤
│ pair_id (FK)     │ pair_123 │ pair_456            │
│ execution_status │ success  │ failed              │
│ output           │ [...]    │ [...]               │
│ duration_ms      │ 1234     │ 5678                │
│ created_at       │ 2024-01  │ 2024-01             │
└──────────────────┴──────────┴─────────────────────┘
```

## Class Diagram

```
PayloadProfile (dataclass)
├── file_type: str
├── payloads: List[str]
├── file_path: str
├── file_name: str
├── file_size: int
├── detected_type: str
├── categories: List[str]
├── generated_at: str
└── profile_id: Optional[str]

ExploitContext (dataclass)
├── file_path: str
├── file_type: str
├── architecture: str
├── suspicious_patterns: List[str]
├── vulnerabilities: List[str]
└── payloads: List[str]

PayloadExploitDB
├── _init_db()
├── save_payload_profile()
├── save_exploit_context()
├── link_payload_to_exploit()
├── get_payload_profile()
├── get_exploit_context()
├── get_linked_pair()
└── list_linked_pairs()

PayloadExploitLinker
├── __init__()
├── create_workflow()
├── get_workflow()
├── update_exploit_code()
├── get_compatible_payloads()
├── export_workflow()
└── export_workflow_with_payloads()
```

## Integration Points

```
exploit_generator_tab.py
├── [LINE 6-37] Import integration module
├── [LINE 589-597] Initialize integration_linker in __init__
├── [LINE 933-939] Call _create_workflow() after exploit generation
├── [LINE 1103-1156] _create_workflow() implementation
└── [LINE 1158-1184] export_workflow() implementation

payload_generator_gui.py
├── [LINE 16-28] Import integration module
├── [LINE 264-281] Initialize integration_linker in __init__
├── [LINE 479-493] Save PayloadProfile in _on_generation_complete()
```

## Error Handling Flow

```
┌─ Integration Operation
│
└─→ TRY
    ├─→ Create/Save/Link
    │  └─→ SUCCESS
    │     └─→ Continue with workflow
    │
    └─→ EXCEPTION
       ├─→ Log warning
       ├─→ Continue with normal operation
       └─→ No impact to user experience
```

## Performance Characteristics

### Database Operations
- Insert payload profile: ~10-50ms
- Insert exploit context: ~10-50ms
- Link pair: ~5-20ms
- Export workflow: ~50-200ms (depends on file sizes)

### Memory Usage
- PayloadProfile: ~5-50KB (depends on payload count)
- ExploitContext: ~5-50KB (depends on string count)
- LinkedPair: ~10-100KB (depends on exploit code size)

### Scalability
- Database: SQLite supports 100,000+ workflows
- UI remains responsive during operations
- Background saving doesn't block user interaction

## Integration Points Summary

| Component | Type | Purpose |
|-----------|------|---------|
| payload_exploit_integration.py | Module | Core integration logic |
| PayloadExploitLinker | Class | Main orchestrator |
| PayloadProfile | Dataclass | Payload storage |
| ExploitContext | Dataclass | Context storage |
| PayloadExploitDB | Class | Database management |
| exploit_generator_tab.py | Modified | Integration entry point |
| payload_generator_gui.py | Modified | Integration entry point |

## Summary

The integration creates a seamless bridge between:
1. **Payload Generation** → Saves profiles to database
2. **Exploit Generation** → Creates contexts and links to payloads
3. **Workflow Management** → Stores complete workflows
4. **Export Functionality** → Exports all data together

All operations are **non-blocking**, **graceful**, and **transparent** to the user.
