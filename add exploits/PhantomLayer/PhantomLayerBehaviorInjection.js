// === PhantomLayer Behavior Injection ===

// Patch IntersectionObserver to instantly trigger observed elements
const _IO = window.IntersectionObserver;
window.IntersectionObserver = function (callback, options) {
    const observer = new _IO((entries, observerInstance) => {
        const fakeEntries = entries.map(entry => ({
            ...entry,
            isIntersecting: true,
        }));
        callback(fakeEntries, observerInstance);
    }, options);
    observer.observe = function (target) {
        callback([{ isIntersecting: true, target }], observer);
    };
    return observer;
};

// Force all elements to be visible
[...document.querySelectorAll('*')].forEach(el => {
    try {
        el.style.display = 'block';
        el.style.visibility = 'visible';
        el.style.opacity = '1';
        el.style.transform = 'none';
    } catch { }
});

// Hijack timeout and idle callbacks to execute immediately
const _setTimeout = window.setTimeout;
window.setTimeout = function (fn, delay, ...args) {
    return _setTimeout(fn, 0, ...args);
};

window.requestIdleCallback = function (fn) {
    return fn({ didTimeout: false, timeRemaining: () => 50 });
};

// Stub common lazyload libraries
window.lozad = () => ({ observe: () => console.log('lozad hijacked') });
window.lazySizes = { init: () => console.log('lazySizes hijacked') };

// Simulate interaction and reveal logic
window.scrollTo(0, document.body.scrollHeight);
['click', 'mousemove', 'keydown'].forEach(evt => {
    document.dispatchEvent(new Event(evt));
});

// Preload lazy images and crawl links
[...document.querySelectorAll('img[data-src], img[data-lazy-src], img[loading="lazy"]')].forEach(img => {
    img.src = img.dataset.src || img.dataset.lazySrc;
    img.loading = 'eager';
});

[...document.querySelectorAll('a[href]')].forEach(link => {
    fetch(link.href).catch(() => { });
});

// === Obfuscated Eval Gate ===
(function gate() {
    const payload = `(() => {
    console.log('Eval gate activated.');
    // Add custom recon logic or code injection here
    // Example: window.__PHANTOM_FLAG__ = 'intercepted';
  })()`;

    const cipher = btoa(payload); // base64 encode as obfuscation
    const decoded = atob(cipher);
    eval(decoded);
})();
