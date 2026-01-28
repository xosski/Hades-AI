# Network Share Integration Guide

## Quick Start (5 minutes)

### Step 0 (Optional): Verify Dependencies
```bash
python verify_network_deps.py
```

This checks and auto-installs required `cryptography` module.

If auto-install fails, manually install:
```bash
pip install cryptography
```

Or use the provided installer:
- **Windows:** `install_network_deps.bat`
- **Linux/Mac:** `bash install_network_deps.sh`

### Step 1: Run Database Migration
```bash
python migrate_db_for_network.py
```

This adds `source_instance` tracking columns to your database.

**Output:**
```
Migration successful!
You can now enable Network Sharing in the GUI
```

### Step 2: Add Network Share Tab to HadesAI.py

Edit `HadesAI.py` and find the `MainWindow.__init__` method where tabs are created.

Add these imports at the top of the file:
```python
from network_share_gui import NetworkShareTab
```

Find the tab creation section (around line 1000-1200) and add:
```python
# Network Share Tab
self.network_share_tab = NetworkShareTab(db_path="hades_knowledge.db")
self.tabs.addTab(self.network_share_tab, "🌐 Network Share")
```

### Step 3: Restart HadesAI

```bash
python HadesAI.py
```

You'll see a new **"🌐 Network Share"** tab.

### Step 4: Enable & Configure

1. Open the Network Share tab
2. Check **"Enable Encrypted P2P Knowledge Sharing"**
3. Update **Instance ID** (e.g., `Hades-Lab-01`)
4. Click to confirm
5. Network node will start with TLS certificates auto-generated

### Step 5: Add Trusted Peers

For each other HadesAI instance you trust:

1. Get peer's hostname/IP and Instance ID
2. Enter in "Add Peer" section:
   - Hostname: `192.168.1.100`
   - Port: `19999`
   - Instance ID: `Hades-Lab-02`
3. Click **"Add Trusted Peer"**
4. Verify success message

### Step 6: Sync Knowledge

**Option A: Sync from all peers**
- Click **"Sync From All Peers"**
- Watch sync log for progress

**Option B: Sync from one peer**
- Select peer in table
- Click **"Sync From Selected"**

Done! Your databases are now synchronized.

---

## Detailed Integration Steps

### File Locations After Integration

```
Hades-AI/
├── HadesAI.py                          (modified - add tab)
├── network_share_gui.py                (NEW)
├── migrate_db_for_network.py           (NEW)
├── NETWORK_SHARE.md                    (NEW)
├── NETWORK_INTEGRATION.md              (NEW)
├── network_config.json                 (NEW - config template)
├── modules/
│   ├── knowledge_network.py            (NEW)
│   └── ... (existing modules)
├── network_certs/                      (AUTO-CREATED)
│   ├── server.crt
│   └── server.key
├── db_backups/                         (AUTO-CREATED)
│   └── hades_knowledge_*.db            (timestamped backups)
└── hades_knowledge.db                  (modified - added columns)
```

### Code Changes to HadesAI.py

#### Import Section
Add at the top with other imports:
```python
from network_share_gui import NetworkShareTab
```

#### MainWindow.__init__ Method
Find where tabs are created (look for `QTabWidget()`), add:

```python
# ... after other tabs like code_analysis_tab, threat_findings_tab, etc ...

# Network Share Tab
try:
    self.network_share_tab = NetworkShareTab(db_path=self.db_path)
    self.tabs.addTab(self.network_share_tab, "🌐 Network Share")
except Exception as e:
    logger.warning(f"Failed to load Network Share tab: {e}")
```

Ensure `self.db_path` is set to your database path (usually `"hades_knowledge.db"`).

#### Cleanup on Exit
If you have a cleanup/exit method, add:

```python
def closeEvent(self, event):
    # ... existing cleanup code ...
    
    # Stop network node
    if hasattr(self, 'network_share_tab') and self.network_share_tab.network_node:
        try:
            self.network_share_tab.network_node.stop()
        except:
            pass
    
    event.accept()
```

---

## Programmatic Usage (Without GUI)

### Initialize and Start Network

```python
from modules.knowledge_network import KnowledgeNetworkNode

# Create node
node = KnowledgeNetworkNode(
    instance_id="Hades-Production-01",
    db_path="hades_knowledge.db",
    port=19999,
    discovery_port=8888
)

# Start the network
if node.start():
    print("Network node started successfully")
else:
    print("Failed to start network node")
```

### Add Peers Programmatically

```python
# Manually add trusted peers
node.add_trusted_peer(
    instance_id="Hades-Production-02",
    hostname="192.168.1.100",
    port=19999
)

node.add_trusted_peer(
    instance_id="Hades-Production-03",
    hostname="hades-03.local",
    port=19999
)
```

### Sync Databases

```python
# Sync from specific peer
result = node.sync_from_peer("Hades-Production-02")
print(f"Merged patterns: {result.get('patterns_merged', 0)}")
print(f"Merged findings: {result.get('findings_merged', 0)}")

# Sync from all peers at once
results = node.sync_all_peers()
for peer_id, stats in results.items():
    print(f"{peer_id}: {stats}")
```

### Check Status

```python
status = node.get_status()
print(f"Instance: {status['instance_id']}")
print(f"Enabled: {status['enabled']}")
print(f"Trusted peers: {status['trusted_peers']}")
print(f"Database hash: {status['db_hash']}")
```

### Stop Network

```python
node.stop()
print("Network node stopped")
```

---

## Requirements

### Dependencies
The network share feature requires:
- `cryptography` - TLS certificate generation (auto-installed on first use)
- `requests` - HTTP discovery (optional)
- Python 3.8+

### Auto-Install
The Network Share tab automatically installs `cryptography` when you first try to enable it.

If you prefer to pre-install:
```bash
python verify_network_deps.py
```

Or manually:
```bash
pip install cryptography requests
```

### Network Requirements
- **Firewall:** Allow ports 19999 (TLS) and 8888 (discovery) between instances
- **Network:** All instances must be on same LAN or VPN
- **Hostname Resolution:** Hostnames/IPs must be resolvable between instances

---

## Testing the Integration

### Test 1: Single Instance
```bash
python -c "
from modules.knowledge_network import KnowledgeNetworkNode
node = KnowledgeNetworkNode('Test-01', 'hades_knowledge.db')
node.start()
status = node.get_status()
print(f'✓ Node started: {status}')
node.stop()
"
```

### Test 2: Certificate Generation
```bash
python -c "
from modules.knowledge_network import CertificateManager
cm = CertificateManager()
cert_path, key_path = cm.get_or_create_cert('test-instance')
fingerprint = cm.get_cert_fingerprint(cert_path)
print(f'✓ Certificate generated')
print(f'✓ Fingerprint: {fingerprint[:16]}...')
"
```

### Test 3: Database Sync (Local)
```bash
python -c "
from modules.knowledge_network import DatabaseSyncProtocol
import sqlite3
import shutil

# Create test databases
src = 'hades_knowledge.db'
test = 'test_remote.db'
shutil.copy2(src, test)

# Try merge
sync = DatabaseSyncProtocol(src, 'instance-1')
stats = sync.merge_database(test, 'instance-2')
print(f'✓ Merge successful: {stats}')

import os
os.remove(test)
"
```

---

## Troubleshooting Integration

### Tab Not Appearing
- Check import statement: `from network_share_gui import NetworkShareTab`
- Ensure `network_share_gui.py` is in the same directory as `HadesAI.py`
- Check console for import errors

### "No module named 'cryptography'"
```bash
pip install cryptography
```

### Network Node Won't Start
1. Check ports 19999 and 8888 are not in use:
   ```bash
   netstat -an | grep 19999
   netstat -an | grep 8888
   ```
2. Check firewall allows local connections
3. Check logs for specific errors

### Can't Connect to Peer
1. Verify peer instance is running and network enabled
2. Test connectivity: `ping <peer_hostname>`
3. Verify ports match (default 19999)
4. Check firewall rules

### Database Merge Fails
1. Ensure source database isn't being modified
2. Check disk space available
3. Restore from backup if corrupted:
   ```bash
   cp db_backups/hades_knowledge_*.db hades_knowledge.db
   ```

---

## Configuration File (Optional)

Use `network_config.json` to pre-configure network settings:

```json
{
  "network_share": {
    "enabled": false,
    "instance_id": "Hades-Lab-01",
    "tls_port": 19999,
    "discovery_port": 8888,
    "trusted_peers": [
      {
        "instance_id": "Hades-Lab-02",
        "hostname": "192.168.1.100",
        "port": 19999,
        "enabled": true
      }
    ]
  }
}
```

Load in your code:
```python
import json
with open('network_config.json') as f:
    config = json.load(f)['network_share']

node = KnowledgeNetworkNode(
    instance_id=config['instance_id'],
    db_path="hades_knowledge.db",
    port=config['tls_port'],
    discovery_port=config['discovery_port']
)
```

---

## Security Best Practices

✅ **DO:**
- Use unique instance IDs per machine
- Manually verify each peer before adding
- Keep certificates in `network_certs/` (don't commit)
- Only enable on private networks
- Regularly backup databases

❌ **DON'T:**
- Expose ports 19999/8888 to the internet
- Use default passwords or instance IDs
- Share certificate files
- Auto-discover/auto-connect peers
- Trust unverified instance connections

---

## Production Deployment

For production environments:

1. **Pre-migration:**
   ```bash
   python migrate_db_for_network.py
   ```

2. **Configuration:**
   - Update `network_config.json` with your instances
   - Set static IPs/hostnames
   - Document instance IDs and network topology

3. **Monitoring:**
   - Enable debug logging
   - Monitor network traffic
   - Track database sizes

4. **Backup Strategy:**
   - Keep `db_backups/` cleaned up (monthly rotation)
   - Store backups separately from instances
   - Test restore procedures

---

## Disabling Network Sharing

To disable:

1. **GUI:** Uncheck "Enable Encrypted P2P Knowledge Sharing"
2. **Programmatic:** Call `node.stop()`
3. **Cleanup:** Databases remain intact, no data loss

To fully remove:
```bash
rm -rf network_certs/
rm -f network_config.json
# Databases and backups remain for recovery
```

---

## Support & Debugging

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("KnowledgeNetwork").setLevel(logging.DEBUG)
```

Check for errors:
- Console output in terminal
- Database integrity: `python migrate_db_for_network.py` (no errors = good)
- Network connectivity: `ping` and `telnet` to peers

---

**Last Updated:** 2026-01-27  
**Version:** 1.0
