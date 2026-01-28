# Network Share - Quick Start (2 Minutes)

## Before You Start

✓ HadesAI installed and running  
✓ Python 3.8+  
✓ Network connectivity between instances

## The Fastest Way

### 1️⃣ Add Tab to HadesAI.py

Find `MainWindow.__init__` method in `HadesAI.py` and add these two lines:

```python
from network_share_gui import NetworkShareTab
```

Then in the tab creation section, add:

```python
self.network_share_tab = NetworkShareTab(db_path="hades_knowledge.db")
self.tabs.addTab(self.network_share_tab, "🌐 Network Share")
```

### 2️⃣ Start HadesAI

```bash
python HadesAI.py
```

### 3️⃣ Enable Network Share

- Go to **"🌐 Network Share"** tab
- Check **"Enable Encrypted P2P Knowledge Sharing"**
- Wait for auto-install if needed (first time only)
- May need to restart HadesAI

### 4️⃣ Add First Peer

In the **"Add Peer"** section:
- **Hostname:** IP or hostname of other HadesAI instance
- **Port:** 19999 (default)
- **Instance ID:** e.g., `Hades-Lab-02`
- Click **"Add Trusted Peer"**

### 5️⃣ Sync

Click **"Sync From All Peers"** to start syncing databases.

## Done! 🎉

Your instances are now sharing knowledge securely.

---

## Auto-Install During Setup

If `cryptography` is missing:
1. First time you enable Network Share, system auto-installs it
2. Shows orange status: "Module Loading..."
3. After install, **restart HadesAI**
4. Module loads automatically on next launch

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No module cryptography" | Restart HadesAI (auto-install happened) |
| Can't connect to peer | Check firewall allows port 19999 |
| Sync fails | Ensure peer instance is running |
| Tab doesn't appear | Ensure `from network_share_gui import NetworkShareTab` added |

## That's All!

For more details, see:
- **NETWORK_INTEGRATION.md** - Full setup guide
- **NETWORK_DEPENDENCIES.md** - Dependency help
- **NETWORK_SHARE.md** - Complete documentation

## Multi-Instance Example

**Instance 1 (Lab-01):**
```
🌐 Network Share → Enable
Instance ID: Hades-Lab-01
Port: 19999
```

**Instance 2 (Lab-02):**
```
🌐 Network Share → Enable
Instance ID: Hades-Lab-02
Port: 19999

Add Peer:
  Hostname: 192.168.1.50 (Lab-01's IP)
  Port: 19999
  Instance ID: Hades-Lab-01
  → Click "Add Trusted Peer"
```

**Sync:**
```
Lab-02 → Click "Sync From All Peers"
Lab-01's database merges into Lab-02
Auto-deduplicates patterns/findings
```

---

**Status:** Ready to use  
**Time:** ~2-5 minutes total setup  
**Auto-install:** ✓ Yes
