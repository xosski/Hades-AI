import os
import sys
import reg
const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
class customsetup:
    def __init__(self, name, version):
self.name = name
self.version = version
    def logging(self, message):
print(f"{self.name} {self.version}: {message}")
    def remote(self, command):
        reg address = "http://example.com/remote"
self.register(address, command)
    def register(self, address, command):
self.logging(f"Registering command '{command}' at {address}")
reg.add("\\<ip_address>\HKCU\Software\Microsoft\Windows\CurrentVersion\Run", self.name, command)
reg.xcopy("\\<ip_address>\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\RegisteredApplications", self.name)
        # Simulate a remote registration
response = f"Command '{command}' registered successfully at {address}"
self.logging(response)

class DeviceEmulator {
    constructor(name, version) {
        this.name = name;
        this.version = version;
        this.registryEntries = new Map(); // Simulate registry storage
    }

    logging(message) {
        console.log(`${this.name} ${this.version}: ${message}`);
    }

    remote(command) {
        const address = "http://example.com/remote";
        this.register(address, command);
    }

    register(address, command) {
        this.logging(`Registering command '${command}' at ${address}`);

        // Simulate Windows registry operations
        this.registryAdd(`\\<ip_address>\\HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`, this.name, command);
        this.registryCopy(`\\<ip_address>\\HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\RegisteredApplications`, this.name);

        // Simulate a remote registration HTTP request
        this.simulateHttpRequest(address, command)
            .then(response => {
                this.logging(response);
            })
            .catch(error => {
                this.logging(`Error: ${error.message}`);
            });
    }

    registryAdd(path, name, value) {
        // Simulate adding to Windows registry
        this.registryEntries.set(`${path}\\${name}`, value);
        this.logging(`Registry: Added ${name} = ${value} to ${path}`);
    }

    registryCopy(path, name) {
        // Simulate copying registry keys
        this.registryEntries.set(`${path}\\${name}`, true);
        this.logging(`Registry: Copied ${name} to ${path}`);
    }

    simulateHttpRequest(address, command) {
        return new Promise((resolve) => {
            // Simulate network delay
            setTimeout(() => {
                resolve(`Command '${command}' registered successfully at ${address}`);
            }, 500);
        });
    }

    // Get device information
    getDeviceInfo() {
        return {
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            cpus: os.cpus().length,
            memory: Math.round(os.totalmem() / (1024 * 1024 * 1024)) + ' GB',
            uptime: Math.round(os.uptime() / 3600) + ' hours'
        };
    }

    // Simulate device startup
    startup() {
        this.logging('Device starting up...');
        const deviceInfo = this.getDeviceInfo();
        this.logging(`Device information: ${JSON.stringify(deviceInfo, null, 2)}`);
        return deviceInfo;
    }
}

// Example usage
const emulator = new DeviceEmulator('DeviceEmulator', '1.0.0');
emulator.startup();
emulator.remote('node device-monitor.js --background');

// Export the emulator class
module.exports = DeviceEmulator;

Copy

Apply

device - emulator.js
And here's a companion device monitor script that could be used with the emulator:

const os = require('os');
const DeviceEmulator = require('./device-emulator');

class DeviceMonitor {
    constructor() {
        this.emulator = new DeviceEmulator('DeviceMonitor', '1.0.0');
        this.interval = null;
        this.stats = {
            startTime: Date.now(),
            commandsProcessed: 0,
            lastActivity: null
        };
    }

    start(intervalMs = 5000) {
        this.emulator.logging('Starting device monitoring...');

        this.interval = setInterval(() => {
            this.checkStatus();
            this.stats.commandsProcessed++;
            this.stats.lastActivity = new Date().toISOString();
        }, intervalMs);

        // Register this monitor to run at startup
        this.emulator.remote(`node ${__filename} --background`);
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
            this.emulator.logging('Device monitoring stopped');
        }
    }

    checkStatus() {
        const memUsage = process.memoryUsage();
        const cpuUsage = os.loadavg();

        this.emulator.logging(`
Status Report:
- Memory: ${Math.round(memUsage.rss / 1024 / 1024)} MB
- CPU Load (1m): ${cpuUsage[0].toFixed(2)}
- Uptime: ${Math.round((Date.now() - this.stats.startTime) / 1000 / 60)} minutes
- Commands Processed: ${this.stats.commandsProcessed}


// Check if running in background mode
const isBackground = process.argv.includes('--background');

// Create and start the monitor
const monitor = new DeviceMonitor();
monitor.start();

if (!isBackground) {
  console.log('Device monitor running in foreground mode. Press Ctrl+C to exit.');
} else {
  console.log('Device monitor running in background mode.');
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  monitor.stop();
  console.log('Device monitor shut down.');
  process.exit(0);
});
class RegistryHandler {
  constructor(simulationMode = false) {
    this.simulationMode = simulationMode || os.platform() !== 'win32';
    this.registryEntries = new Map(); // For simulation mode
    
    if (this.simulationMode) {
      console.log('Registry Handler running in simulation mode');
    } else {
      console.log('Registry Handler running in real mode on Windows');
    }
  }

  // Add a value to the Windows registry
  add(regPath, name, value) {
    if (this.simulationMode) {
      return this._simulateAdd(regPath, name, value);
    } else {
      return this._realAdd(regPath, name, value);
    }
  }

  // Copy registry keys
  xcopy(sourcePath, keyName) {
    if (this.simulationMode) {
      return this._simulateXcopy(sourcePath, keyName);
    } else {
      return this._realXcopy(sourcePath, keyName);
    }
  }

  // Simulate adding to registry (for non-Windows platforms)
  _simulateAdd(regPath, name, value) {
    const fullPath = `${ regPath }\\${ name }`;
    this.registryEntries.set(fullPath, value);
    console.log(`[SIMULATION] Added registry key: ${ fullPath } = ${ value }`);
    return Promise.resolve({ success: true, path: fullPath, value });
  }

  // Simulate copying registry keys (for non-Windows platforms)
  _simulateXcopy(sourcePath, keyName) {
    const fullPath = `${ sourcePath }\\${ keyName }`;
    this.registryEntries.set(fullPath, true);
    console.log(`[SIMULATION] Copied registry key: ${ keyName } to ${ sourcePath }`);
    return Promise.resolve({ success: true, path: fullPath });
  }

  // Real registry add operation (Windows only)
  _realAdd(regPath, name, value) {
    // Parse the registry path to extract the hive and subkey
    const pathParts = regPath.split('\\');
    let hiveName = pathParts[pathParts.length > 0 ? 1 : 0]; // Skip the server name if present
    
    // Normalize the hive name
    if (hiveName.includes('HKCU')) hiveName = 'HKCU';
    if (hiveName.includes('HKEY_CURRENT_USER')) hiveName = 'HKCU';
    if (hiveName.includes('HKLM')) hiveName = 'HKLM';
    if (hiveName.includes('HKEY_LOCAL_MACHINE')) hiveName = 'HKLM';
    
    // Extract the subkey (everything after the hive)
    const subkeyIndex = regPath.indexOf(hiveName) + hiveName.length + 1;
    const subkey = regPath.substring(subkeyIndex);
    
    // Build the REG ADD command
    const command = `REG ADD "${hiveName}\\${subkey}" / v "${name}" / d "${value}" / f`;
    
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`Registry add error: ${ error.message }`);
          reject(error);
          return;
        }
        if (stderr) {
          console.error(`Registry add stderr: ${ stderr }`);
          reject(new Error(stderr));
          return;
        }
        console.log(`Registry key added: ${ hiveName }\\${ subkey }\\${ name }`);
        resolve({ success: true, output: stdout });
      });
    });
  }

  // Real registry copy operation (Windows only)
  _realXcopy(sourcePath, keyName) {
    // Parse the source path
    const pathParts = sourcePath.split('\\');
    let hiveName = pathParts[pathParts.length > 0 ? 1 : 0]; // Skip the server name if present
    
    // Normalize the hive name
    if (hiveName.includes('HKCU')) hiveName = 'HKCU';
    if (hiveName.includes('HKEY_CURRENT_USER')) hiveName = 'HKCU';
    if (hiveName.includes('HKLM')) hiveName = 'HKLM';
    if (hiveName.includes('HKEY_LOCAL_MACHINE')) hiveName = 'HKLM';
    
    // Extract the subkey (everything after the hive)
    const subkeyIndex = sourcePath.indexOf(hiveName) + hiveName.length + 1;
    const subkey = sourcePath.substring(subkeyIndex);
    
    // For xcopy, we'll simulate by creating an empty key
    const command = `REG ADD "${hiveName}\\${subkey}\\${keyName}" / f`;
    
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`Registry xcopy error: ${ error.message }`);
          reject(error);
          return;
        }
        if (stderr) {
          console.error(`Registry xcopy stderr: ${ stderr }`);
          reject(new Error(stderr));
          return;
        }
        console.log(`Registry key copied: ${ hiveName }\\${ subkey }\\${ keyName }`);
        resolve({ success: true, output: stdout });
      });
    });
  }

  // Get all registry entries (simulation mode only)
  getAllEntries() {
    if (!this.simulationMode) {
      return Promise.reject(new Error('getAllEntries is only available in simulation mode'));
    }
    
    const entries = {};
    this.registryEntries.forEach((value, key) => {
      entries[key] = value;
    });
    
    return Promise.resolve(entries);
  }
}

module.exports = RegistryHandler;

Copy

Apply

registry-handler.js
Now, let's update the DeviceEmulator class to use this registry handler:

const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
const RegistryHandler = require('./registry-handler');

class DeviceEmulator {
  constructor(name, version, simulateRegistry = false) {
    this.name = name;
    this.version = version;
    this.registry = new RegistryHandler(simulateRegistry);
  }

  logging(message) {
    console.log(`${ this.name } ${ this.version }: ${ message }`);
  }

  remote(command) {
    const address = "http://example.com/remote";
    this.register(address, command);
  }

  async register(address, command) {
    this.logging(`Registering command '${command}' at ${ address }`);
    
    try {
      // Add to Windows startup registry
      await this.registry.add(
        "\\\\<ip_address>\\HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        this.name, 
        command
      );
      
      // Copy to registered applications
      await this.registry.xcopy(
        "\\\\<ip_address>\\HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\RegisteredApplications", 
        this.name
      );
      
      // Simulate a remote registration HTTP request
      const response = await this.simulateHttpRequest(address, command);
      this.logging(response);
    } catch (error) {
      this.logging(`Error during registration: ${ error.message }`);
    }
  }

  simulateHttpRequest(address, command) {
    return new Promise((resolve) => {
      // Simulate network delay
      setTimeout(() => {
        resolve(`Command '${command}' registered successfully at ${ address }`);
      }, 500);
    });
  }

  // Get device information
  getDeviceInfo() {
    return {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      cpus: os.cpus().length,
      memory: Math.round(os.totalmem() / (1024 * 1024 * 1024)) + ' GB',
      uptime: Math.round(os.uptime() / 3600) + ' hours'
    };
  }

  // Simulate device startup
  startup() {
    this.logging('Device starting up...');
    const deviceInfo = this.getDeviceInfo();
    this.logging(`Device information: ${ JSON.stringify(deviceInfo, null, 2) }`);
    return deviceInfo;
  }

  // Create a custom application environment
  createCustomEnvironment(appName, appPath) {
    this.logging(`Creating custom environment for ${ appName }`);
    
    // Create app directory if it doesn't exist
    if (!fs.existsSync(appPath)) {
      fs.mkdirSync(appPath, { recursive: true });
      this.logging(`Created application directory: ${ appPath } `);
    }
    
    // Create a configuration file for the custom app
    const configPath = path.join(appPath, 'config.json');
    const config = {
      appName: appName,
      createdBy: this.name,
      version: this.version,
      created: new Date().toISOString(),
      deviceInfo: this.getDeviceInfo(),
      registryEntries: {
        startup: `\\\\<ip_address>\\HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\${this.name}`,
            registered: `\\\\<ip_address>\\HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\RegisteredApplications\\${this.name}`
      }
    };

                fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
                this.logging(`Created configuration file: ${configPath}`);

                // Register the custom app to run at startup
                const startupCommand = `node ${path.join(appPath, 'app.js')} --background`;
                this.remote(startupCommand);

                // Create a basic app.js file
                const appJsPath = path.join(appPath, 'app.js');
                const appJsContent = `
                const fs = require('fs');
                const path = require('path');
                const DeviceEmulator = require('${path.relative(appPath, __filename)}');

                // Load configuration
                const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));

                // Create emulator instance
                const emulator = new DeviceEmulator(config.appName, config.version);

                // Log startup
                console.log(\`\${config.appName} starting up...\`);
                console.log(\`Configuration: \${JSON.stringify(config, null, 2)}\`);

                // Check if running in background mode
                const isBackground = process.argv.includes('--background');
                if (isBackground) {
                    console.log(\`\${config.appName} running in background mode\`);
} else {
                    console.log(\`\${config.appName} running in foreground mode. Press Ctrl+C to exit.\`);
}

                // Main application logic
                function runApp() {
                    console.log(\`\${config.appName} is running...\`);

  // Your custom application code here

  // Example: periodic status check
  setInterval(() => {
    const memUsage = process.memoryUsage();
                console.log(\`Memory usage: \${Math.round(memUsage.rss / 1024 / 1024)} MB\`);
  }, 60000);
}

                // Start the application
                runApp();

// Handle graceful shutdown
process.on('SIGINT', () => {
                    console.log(\`\${config.appName} shutting down...\`);
                process.exit(0);
});
                `;

                fs.writeFileSync(appJsPath, appJsContent);
                this.logging(`Created application file: ${appJsPath}`);

                return {
                    appName,
                    appPath,
                    configPath,
                    appJsPath
                };
  }
}

                // Example usage
                if (require.main === module) {
  const emulator = new DeviceEmulator('DeviceEmulator', '1.0.0', true);
                emulator.startup();

                // Create a custom application environment
                const appInfo = emulator.createCustomEnvironment(
                'CustomApp',
                path.join(__dirname, 'custom-app')
                );

                console.log('Custom application created:', appInfo);
}

                // Export the emulator class
                module.exports = DeviceEmulator;