// build-pipeline.js
import { execSync } from 'child_process';
import fs from 'fs';

const MODULE_NAME = 'PhantomLayer';
const ENTRY_FILE = './src/PhantomLayer.js';
const OUTPUT_DIR = './dist';
const BUNDLE_FILE = `${OUTPUT_DIR}/${MODULE_NAME}.bundle.js`;

function ensureOutputDir() {
    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }
}

function bundleModule() {
    console.log(`[+] Bundling ${MODULE_NAME}...`);
    execSync(`esbuild ${ENTRY_FILE} --bundle --minify --outfile=${BUNDLE_FILE}`, {
        stdio: 'inherit',
    });
}

function injectBanner() {
    const banner = `/**\n * ${MODULE_NAME} - PhantomLayer Obfuscation Module\n * Auto-injected @ ${new Date().toISOString()}\n */\n`;
    const content = fs.readFileSync(BUNDLE_FILE, 'utf-8');
    fs.writeFileSync(BUNDLE_FILE, banner + content);
    console.log('[+] Banner injected.');
}

function main() {
    ensureOutputDir();
    bundleModule();
    injectBanner();
    console.log(`[+] Build complete. Output: ${BUNDLE_FILE}`);
}

main();
