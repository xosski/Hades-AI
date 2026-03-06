// 🧬 GhostShell Fragment Generator (Node/Browser compatible)

function generateFragments(rawCode, chunkSize = 64) {
    const b64 = btoa(rawCode);
    const fragments = [];
    for (let i = 0; i < b64.length; i += chunkSize) {
        const chunk = b64.slice(i, i + chunkSize);
        fragments.push(`injectGhostFragment(${fragments.length}, "${chunk}");`);
    }
    return fragments.join('\n');
}

// Example Usage (Browser Console)
// const code = 'alert("👻 GhostShell loaded")';
// console.log(generateFragments(code));

// Export for Node.js if needed
if (typeof module !== 'undefined') module.exports = { generateFragments };
