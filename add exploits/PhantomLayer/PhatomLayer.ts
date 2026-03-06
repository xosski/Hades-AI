// PhantomLayer React Template
// GhostCore Defense Artifact

import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";

const isGhost = () => {
    try {
        const t = performance.now();
        const ua = navigator.userAgent;
        const entropy = t > 100 && !/HeadlessChrome|PhantomJS/i.test(ua);
        return !entropy;
    } catch {
        return true;
    }
};

const eraseFingerprint = () => {
    try {
        localStorage.clear();
        sessionStorage.clear();
        indexedDB.databases().then(dbs => dbs.forEach(db => indexedDB.deleteDatabase(db.name)));
    } catch (e) {
        console.warn("Fingerprint erasure failed:", e);
    }
};

const deployPhantom = () => {
    document.body.innerHTML = "<div style='display:none'>PhantomLayer Active</div>";
    document.title = "";
    eraseFingerprint();
};

const useAntiScraper = () => {
    useEffect(() => {
        if (isGhost()) {
            deployPhantom();
        }
    }, []);
};

const App = () => {
    useAntiScraper();

    const ref = useRef(null);
    const [status, setStatus] = useState("loading");

    useEffect(() => {
        const timer = setTimeout(() => {
            setStatus("ready");
        }, 300);
        return () => clearTimeout(timer);
    }, []);

    return (
        <main ref= { ref } >
        <h1>GhostCore: PhantomLayer </h1>
            < p > Status: { status } </p>
                </main>
  );
};

const root = createRoot(document.getElementById("root"));
root.render(<App />);
