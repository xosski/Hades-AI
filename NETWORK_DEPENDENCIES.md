# Network Share Dependencies & Auto-Install

## Overview

The Network Share feature requires the `cryptography` module for TLS certificate generation.

**Good news:** It auto-installs automatically when you first enable the feature in the GUI.

## Automatic Installation

### How It Works

1. When you **enable Network Share** in HadesAI GUI, the system checks for `cryptography`
2. If missing, it **automatically installs** it via pip
3. After install, you may need to **restart HadesAI** to load the module
4. Network node will start successfully

### What Happens Behind the Scenes

```python
# network_share_gui.py does this automatically:

def ensure_cryptography():
    try:
        import cryptography
        return True
    except ImportError:
        return install_cryptography()

def install_cryptography():
    subprocess.call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
    return True
```

## Manual Installation

If auto-install doesn't work, install manually:

### Option 1: Using Python
```bash
python -m pip install cryptography
```

### Option 2: Using provided scripts

**Windows:**
```bash
install_network_deps.bat
```

**Linux/Mac:**
```bash
bash install_network_deps.sh
```

### Option 3: Manual pip
```bash
pip install cryptography
```

## Verify Installation

Check that everything is installed:

```bash
python verify_network_deps.py
```

**Output if successful:**
```
============================================================
HadesAI Network Share - Dependency Verification
============================================================

Checking dependencies...
✓ cryptography (v42.0.0)
✓ sqlite3 (vunknown)
✓ ssl (vunknown)
✓ socket (vunknown)
✓ http.server (v0.6)

✓ All dependencies satisfied!

You can now use Network Share feature:
  1. Enable in HadesAI GUI -> Network Share tab
  2. Configure instance ID and ports
  3. Add trusted peers
  4. Sync databases
============================================================
```

## Troubleshooting

### "No module named 'cryptography'" Error

The module wasn't installed. Try:

1. **Automatic install** (recommended):
   ```bash
   python -m pip install cryptography
   ```

2. **If that fails**, check your Python installation:
   ```bash
   python --version
   python -m pip --version
   ```

3. **Restart HadesAI** after installing

### "Failed to install cryptography" in GUI

Shows when auto-install attempted but failed. This could be due to:
- Network connectivity issues
- Pip configuration problems
- Permission issues

**Solution:**
```bash
python -m pip install --upgrade cryptography
```

Then restart HadesAI.

### "Permission denied" error

On Linux/Mac, you might need:
```bash
python -m pip install --user cryptography
```

### Module loads but Network Share tab disabled

Auto-install succeeded but module not loaded. **Restart HadesAI.**

## Requirements

- **Python 3.8+** (check with `python --version`)
- **Pip package manager** (usually included with Python)
- **Internet connection** for first install
- **~50MB disk space** for cryptography module

## All Dependencies

| Module | Type | Purpose | Auto-Install |
|--------|------|---------|--------------|
| `cryptography` | External | TLS certificates | ✓ Yes |
| `sqlite3` | Stdlib | Database | ✓ Built-in |
| `ssl` | Stdlib | TLS connections | ✓ Built-in |
| `socket` | Stdlib | Network sockets | ✓ Built-in |
| `http.server` | Stdlib | Discovery server | ✓ Built-in |
| `json` | Stdlib | Data encoding | ✓ Built-in |
| `hashlib` | Stdlib | Hash verification | ✓ Built-in |
| `threading` | Stdlib | Async operations | ✓ Built-in |

## Pip Troubleshooting

### Check pip works
```bash
python -m pip --version
```

### Upgrade pip
```bash
python -m pip install --upgrade pip
```

### Install with verbose output
```bash
python -m pip install cryptography -v
```

### Install from cache (offline)
```bash
# First, download while online:
python -m pip download cryptography -d ./cache

# Then offline:
python -m pip install cryptography --no-index --find-links ./cache
```

## What cryptography Is

The `cryptography` library is a mature Python package that provides:
- X.509 certificate generation (self-signed certs)
- RSA key generation
- TLS context creation
- Hash functions

It's widely used in production systems and open-source.

**Installation size:** ~50MB (includes compiled extensions)

**License:** Apache 2.0 / BSD

## Verification Code

To programmatically check if everything is ready:

```python
def check_network_ready():
    """Check if network sharing is available"""
    try:
        from modules.knowledge_network import KnowledgeNetworkNode
        return True
    except ImportError:
        return False

if check_network_ready():
    print("Network sharing is ready to use!")
else:
    print("Network sharing requires dependencies to be installed")
    print("Run: python verify_network_deps.py")
```

## Next Steps

Once dependencies are installed:

1. Run database migration:
   ```bash
   python migrate_db_for_network.py
   ```

2. Restart HadesAI:
   ```bash
   python HadesAI.py
   ```

3. Enable Network Share in the **"🌐 Network Share"** tab

4. Add trusted peers and sync knowledge

See **NETWORK_INTEGRATION.md** for full setup guide.

---

**Status:** ✅ Auto-install enabled  
**Version:** 1.0  
**Last Updated:** 2026-01-27
