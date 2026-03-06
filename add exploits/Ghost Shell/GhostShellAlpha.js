(function ghostShell() {
    const shellID = 'ghost-shell-' + Math.random().toString(36).substring(2);
    const ttl = 300000; // 5 minutes in ms

    const memory = {
        loaded: Date.now(),
        commands: {},
        whisper: function (msg) {
            console.log('%c[GhostShell]', 'color:#999', msg);
        },
        purge: function () {
            memory.whisper("Self-purge initiated.");
            for (let k in memory) delete memory[k];
            if (typeof window[shellID] !== 'undefined') delete window[shellID];
        }
    };

    function loadCommand(name, fn) {
        memory.commands[name] = fn;
    }

    // Base Commands
    loadCommand('help', () => Object.keys(memory.commands));
    loadCommand('echo', args => args.join(' '));
    loadCommand('time', () => new Date().toISOString());
    loadCommand('purge', memory.purge);

    memory.whisper("GhostShell loaded. Type gs('help')");

    // TTL Self-Wipe
    setTimeout(() => {
        memory.whisper("Time-to-live expired.");
        memory.purge();
    }, ttl);

    // Expose entry point without traceable global
    window[shellID] = function (cmd, ...args) {
        if (memory.commands[cmd]) return memory.commands[cmd](args);
        return '[GhostShell] Unknown command';
    };

    // Alias
    window.gs = window[shellID];

})();