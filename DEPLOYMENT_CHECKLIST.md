# Network Share Feature - Deployment Checklist

## Pre-Deployment

- [ ] Read `QUICK_START_NETWORK.md` (2 min)
- [ ] Read `NETWORK_INTEGRATION.md` § Quick Start (5 min)
- [ ] Verify Python 3.8+ installed: `python --version`
- [ ] Verify pip works: `python -m pip --version`
- [ ] Have network access between instances (ping test)

## Dependency Setup (5 min)

- [ ] Run verification: `python verify_network_deps.py`
- [ ] Confirm output: "✓ All dependencies satisfied!"
- [ ] If failed: Try `pip install cryptography` manually

## Code Integration (10 min)

- [ ] Make backup of `HadesAI.py`
- [ ] Open `HadesAI.py` in editor
- [ ] Find imports section (top ~50 lines)
- [ ] Add network import:
  ```python
  try:
      from network_share_gui import NetworkShareTab
      HAS_NETWORK_SHARE = True
  except ImportError:
      HAS_NETWORK_SHARE = False
      NetworkShareTab = None
  ```
- [ ] Find tab creation section (around line 1000+)
- [ ] Add network share tab:
  ```python
  if HAS_NETWORK_SHARE:
      try:
          self.network_share_tab = NetworkShareTab(db_path=self.db_path)
          self.tabs.addTab(self.network_share_tab, "🌐 Network Share")
      except Exception as e:
          logger.warning(f"Network Share tab failed: {e}")
  ```
- [ ] Save file
- [ ] Test syntax: `python -m py_compile HadesAI.py`
- [ ] No errors shown = ✓

## Database Preparation (5 min)

- [ ] Backup database: `cp hades_knowledge.db hades_knowledge.db.backup`
- [ ] Run migration: `python migrate_db_for_network.py`
- [ ] Confirm output: "Migration successful!"
- [ ] Verify backup created: `ls db_backups/`

## Testing Phase 1 - Single Instance (5 min)

- [ ] Start HadesAI: `python HadesAI.py`
- [ ] Look for new "🌐 Network Share" tab
- [ ] Tab appears = ✓
- [ ] Tab disabled initially = ✓
- [ ] Check "Enable Encrypted P2P Knowledge Sharing"
- [ ] System auto-installs cryptography (watch status)
- [ ] Status changes to "Active" = ✓
- [ ] See network_certs/ directory created = ✓
- [ ] Network status shows ports = ✓
- [ ] Click "Refresh Status" button
- [ ] Displays instance info = ✓
- [ ] Close HadesAI gracefully
- [ ] No errors in console = ✓

## Testing Phase 2 - Multi-Instance (15 min)

### Instance 1 (Lab-01)
- [ ] Start first instance: `python HadesAI.py`
- [ ] Enable Network Share
- [ ] Set Instance ID: `Hades-Lab-01`
- [ ] Note port: `19999`
- [ ] Check status shows "Active"
- [ ] Leave running

### Instance 2 (Lab-02)
- [ ] Start second instance (different terminal)
- [ ] Enable Network Share
- [ ] Set Instance ID: `Hades-Lab-02`
- [ ] Note its IP/hostname
- [ ] In "Add Peer" section:
  - Hostname: `<IP or hostname of Lab-01>`
  - Port: `19999`
  - Instance ID: `Hades-Lab-01`
- [ ] Click "Add Trusted Peer"
- [ ] Success message appears = ✓
- [ ] Peer appears in table = ✓

### Sync Test
- [ ] Select peer in table
- [ ] Click "Sync From Selected"
- [ ] Watch sync log
- [ ] See "Sync complete" message = ✓
- [ ] Statistics show records merged = ✓
- [ ] Database backup created = ✓

## Testing Phase 3 - Firewall & Network (10 min)

- [ ] Both instances on same network
- [ ] Ports 19999 and 8888 accessible
- [ ] Test: `telnet <peer_ip> 19999` works
- [ ] Firewall doesn't block connection
- [ ] Sync succeeds = ✓

## Verification Tests (10 min)

### Test 1: Certificate Generation
```bash
python -c "
from modules.knowledge_network import CertificateManager
cm = CertificateManager()
cert, key = cm.get_or_create_cert('test')
print(f'✓ Certificates: {cert}, {key}')
"
```
- [ ] Output shows certificate paths

### Test 2: Database Merge
```bash
python -c "
from modules.knowledge_network import DatabaseSyncProtocol
sync = DatabaseSyncProtocol('hades_knowledge.db', 'test-instance')
print(f'✓ Sync ready: {sync.db_path}')
"
```
- [ ] No errors

### Test 3: File Transfer Protocol
```bash
python -c "
from modules.knowledge_network import FileTransferProtocol
data = b'test data'
packet = FileTransferProtocol.create_packet(data, '0' * 64)
print(f'✓ Transfer protocol ready: {len(packet)} bytes')
"
```
- [ ] Shows packet size

### Test 4: GUI Module
```bash
python -c "
from network_share_gui import NetworkShareTab, HAS_NETWORK
print(f'✓ GUI loaded: Network={HAS_NETWORK}')
"
```
- [ ] Shows Network=True

## Rollback Plan (Prepare Before Deploy)

- [ ] Database backup: `hades_knowledge.db.backup` ✓
- [ ] HadesAI.py backup: `HadesAI.py.backup` ✓
- [ ] Know how to restore:
  ```bash
  cp hades_knowledge.db.backup hades_knowledge.db
  cp HadesAI.py.backup HadesAI.py
  git checkout HadesAI.py  # If using git
  ```

## Production Deployment

### Setup Monitoring
- [ ] Enable debug logging (see NETWORK_SHARE.md)
- [ ] Monitor disk space for `db_backups/`
- [ ] Check network connectivity monthly
- [ ] Review sync logs periodically

### Configuration
- [ ] Update `network_config.json` with all instances
- [ ] Document instance IDs and IP addresses
- [ ] Set unique Instance IDs (no duplicates)
- [ ] Verify firewall rules allow ports 19999, 8888

### First Production Sync
- [ ] Pick one primary instance
- [ ] Add other instances as trusted peers
- [ ] Start with manual sync (don't auto-sync yet)
- [ ] Verify deduplication works
- [ ] Check database sizes don't explode
- [ ] Monitor for 1 hour after first sync

### Ongoing Operations
- [ ] Weekly: Check db_backups/ size
- [ ] Monthly: Verify sync successful
- [ ] Quarterly: Review and rotate old backups
- [ ] Document any issues encountered

## Sign-Off

| Role | Name | Date | Status |
|------|------|------|--------|
| Implementer | __________ | __/__/__ | [ ] Complete |
| QA/Tester | __________ | __/__/__ | [ ] Verified |
| Ops/Admin | __________ | __/__/__ | [ ] Approved |

---

## Common Issues During Deployment

### Issue: Import error in HadesAI.py
- [ ] Check `from network_share_gui` line added correctly
- [ ] Ensure `network_share_gui.py` in root directory
- [ ] No syntax errors in modified file

### Issue: cryptography not installing
- [ ] Try: `python -m pip install --upgrade cryptography`
- [ ] Check internet connection
- [ ] Check pip working: `python -m pip --version`

### Issue: Tab doesn't appear after restart
- [ ] Check console for error messages
- [ ] Restart HadesAI completely (not just refresh)
- [ ] Check `HAS_NETWORK_SHARE` flag is True

### Issue: Can't connect between instances
- [ ] Ping each other: `ping <other_ip>`
- [ ] Check ports: `telnet <ip> 19999`
- [ ] Verify same network (not separated by NAT)
- [ ] Check firewall rules

### Issue: Sync shows "Hash verification failed"
- [ ] Network corruption unlikely
- [ ] Try sync again
- [ ] Check database files aren't corrupted

## Support Resources

| Issue | Reference |
|-------|-----------|
| General questions | `NETWORK_INTEGRATION.md` |
| Quick setup | `QUICK_START_NETWORK.md` |
| Dependencies | `NETWORK_DEPENDENCIES.md` |
| Architecture | `NETWORK_SHARE.md` |
| Code integration | `HADES_INTEGRATION_SNIPPET.md` |
| File reference | `NETWORK_SHARE_FILES_MANIFEST.md` |

---

## Post-Deployment

- [ ] Document any custom configurations
- [ ] Train users on enabling network share
- [ ] Create runbook for common operations
- [ ] Schedule regular backup rotation
- [ ] Monitor for issues
- [ ] Plan quarterly security updates

---

## Success Criteria

✅ All tests pass  
✅ No console errors  
✅ Multi-instance sync works  
✅ Backups created automatically  
✅ Network certificates generated  
✅ GUI tab fully functional  
✅ Deduplication prevents duplicates  
✅ Network can be toggled on/off  
✅ Graceful error handling  
✅ Documentation complete  

---

**Deployment Checklist Version:** 1.0  
**Last Updated:** 2026-01-27  
**Estimated Time:** 90 minutes total
