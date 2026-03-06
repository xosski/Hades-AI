📘 HOW TO USE: GhostShell
❖ What is GhostShell?
GhostShell is a volatile in-memory shell that runs directly inside a browser’s console. It accepts base64-encoded JavaScript fragments, reassembles them, and executes the payload without writing anything to disk. It's built for stealth, testing, and ephemeral computation.

🚀 Step-by-Step Usage
1. 🔧 Load the Shell
Paste the full GhostShell bootstrap code into your browser console.
Once loaded, you’ll see:
[GHOST SHELL] Initialized. Send fragments via: injectGhostFragment(index, b64payload)
You’re now inside the shell. Memory only. Nothing on disk.

2. 📜 Prepare Your Payload
Write the JavaScript code you want to execute, for example:
console.log("Ghosts are real.");
alert("You’re inside the shell.");
3. 🧪 Encode & Fragment
Convert your code to Base64 and split it into 64-character chunks.

You can use any Base64 encoder — or use the Python/JS auto-generator.

Example:
# Python snippet
import base64, textwrap
payload = 'console.log("Ghosts are real."); alert("You’re inside the shell.");'
encoded = base64.b64encode(payload.encode()).decode()
fragments = textwrap.wrap(encoded, 64)
for i, frag in enumerate(fragments):
    print(f'injectGhostFragment({i}, "{frag}");')
4. ☁️ Inject Fragments
Paste each injectGhostFragment(index, fragment) call into the browser console in any order.

Example:

injectGhostFragment(0, "Y29uc29sZS5sb2coIkdob3N0cyBhcmUgcmVhbC4iKTsKYWxlcnQoIllvdeKAmXJlIGluc2lkZSB0aGUgc2hlbGwuIik7");
5. 🧠 Automatic Reassembly
Once all expected fragments have been injected (default = 10, or set to your count), GhostShell will:

Join all fragments

Decode from Base64

Dynamically execute the result

You’ll see:
[GHOST] Reassembling & executing payload...
…and your payload will run — entirely in volatile memory.

6. 🔥 Auto-Wipe / Self-Destruct
GhostShell includes a TTL purge timer (default: 3 minutes).
After timeout:

All memory is cleared

Shell variables are deleted

Execution context evaporates

You can also call:
gs('purge')
To wipe instantly.

🧰 Additional Commands
After loading, GhostShell exposes a basic CLI:
gs('help')      // Lists commands
gs('echo', 'hi')// Echo utility
gs('time')      // Current timestamp
gs('purge')     // Manual memory purge
🛡️ Safe Defaults
No DOM interaction

No external requests

No persistent variables

No cookies or localStorage use

Fully confined to current browser tab session

