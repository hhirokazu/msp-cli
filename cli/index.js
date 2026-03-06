/**
 * ========================================================================
 * Firewalla MSP API Example: Interactive Cisco-Style CLI
 * ========================================================================
 * This is a zero-dependency script using only built-in Node.js modules.
 * * --- CORE ARCHITECTURAL CONCEPTS DEMONSTRATED ---
 * 1. Global Discovery: Fetching top-level inventories (e.g., /boxes).
 * 2. Scoped Filtering: Passing a Box ID (?box_gid=) to view local devices.
 * 3. The Toggle Paradigm: Instead of creating/deleting complex firewall 
 * rules via API, we find existing rules and simply toggle their state 
 * (/pause or /resume).
 * ========================================================================
 */

const https = require('https');
const readline = require('readline');
const fs = require('fs');

/**
 * --- 1. CONFIGURATION & CREDENTIAL LOADING ---
 * Security Best Practice: Never hardcode API tokens.
 * This helper function looks for credentials in two places:
 * A) Command line variables (e.g., domain="xxx" token="yyy" node index.js)
 * B) Hidden local files (e.g., ./.domain and ./.token)
 */
const getSecret = (key, file) => {
    try {
        return process.env[key] || fs.readFileSync(file).toString().trim();
    } catch (e) {
        return null;
    }
};

const MSP_DOMAIN = getSecret('domain', './.domain');
const API_TOKEN = getSecret('token', './.token');

// Abort the script immediately if credentials are missing
if (!MSP_DOMAIN || !API_TOKEN) {
    console.error('Error: Credentials not found. Provide domain and token via env or files.');
    process.exit(1);
}

// Global Variables
const BASE_URL = `https://${MSP_DOMAIN}/v2`;
const hostname = MSP_DOMAIN.split('.')[0];

// State Management: This variable acts as our "Cisco Context". 
// When set, all commands apply ONLY to this specific firewall.
let currentGid = null;

/**
 * --- 2. THE API COMMUNICATION LAYER ---
 * Because we are not using Axios, we must manually handle the HTTP stream.
 * * @param {string} path - The API endpoint (e.g., '/boxes')
 * @param {string} method - 'GET' (read data) or 'POST' (trigger an action)
 */
function apiRequest(path, method = 'GET') {
    return new Promise((resolve) => {
        const options = {
            method: method,
            headers: {
                // Firewalla MSP requires the exact prefix "Token " before the key
                'Authorization': `Token ${API_TOKEN}`, 
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(`${BASE_URL}${path}`, options, (res) => {
            let data = '';
            
            // Native Node.js receives data in small chunks. We must buffer them together.
            res.on('data', (chunk) => data += chunk);
            
            // Once the stream is finished, parse the complete JSON string
            res.on('end', () => {
                // Accept any successful HTTP code (200 OK, 201 Created, 204 No Content)
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(JSON.parse(data)); } catch (e) { resolve(true); } 
                } else {
                    console.log(`\n% API Error: ${res.statusCode} at ${method} ${path}`);
                    resolve(null);
                }
            });
        });

        // Gracefully handle network drops or DNS issues
        req.on('error', (err) => {
            console.log(`\n% Connection Error: ${err.message}`);
            resolve(null);
        });

        // Action endpoints (like /pause) require a POST request with an empty body.
        // We must explicitly tell the server the body length is 0, or it will hang waiting for data.
        if (method === 'POST') req.setHeader('Content-Length', 0);
        req.end();
    });
}

/**
 * --- 3. API ACTION LOGIC ---
 * These functions map specific CLI commands to their respective REST API calls.
 */

// Command: show inventory
// Fetches the global list of all Firewalla boxes managed by this MSP account.
async function showInventory() {
    console.log(`% Executing: GET ${BASE_URL}/boxes`);
    const boxes = await apiRequest('/boxes');
    if (boxes && Array.isArray(boxes)) {
        console.log(`\n${'NAME'.padEnd(20)} ${'MODEL'.padEnd(10)} ${'STATUS'.padEnd(8)} ${'GID'.padEnd(20)}`);
        console.log("-".repeat(75));
        boxes.forEach(b => {
            console.log(`${(b.name || 'N/A').padEnd(20)} ${(b.model || 'N/A').padEnd(10)} ${(b.online ? 'up' : 'down').padEnd(8)} ${b.gid.padEnd(20)}`);
        });
        console.log("");
    }
}

// Command: show version
// Queries the /boxes endpoint but filters for ONLY the active context GID.
async function showVersion() {
    if (!currentGid) return console.log("% Error: No box selected.");
    console.log(`% Executing: GET ${BASE_URL}/boxes?gid=${currentGid}`);
    const data = await apiRequest(`/boxes?gid=${currentGid}`);
    
    // The API returns an array, even when filtering for a specific ID. We grab the first index [0].
    if (data && data.length > 0) {
        const b = data[0];
        console.log(`\nOS Version: ${b.version || 'N/A'}\nHardware:   ${b.model || 'N/A'}\nStatus:     ${b.online ? 'Online' : 'Offline'}\n`);
    }
}

// Command: show device br
// Requires a context. Passing ?box_gid= ensures we don't accidentally ask the 
// API to return every device across the entire MSP fleet at once.
async function showDeviceBrief() {
    if (!currentGid) return console.log("% Error: No box selected.");
    console.log(`% Executing: GET ${BASE_URL}/devices?box_gid=${currentGid}`);
    const devices = await apiRequest(`/devices?box_gid=${currentGid}`);
    
    if (devices && Array.isArray(devices)) {
        console.log(`\n${'HOSTNAME'.padEnd(25)} ${'IP ADDRESS'.padEnd(18)} ${'MAC ADDRESS'.padEnd(18)}`);
        console.log("-".repeat(65));
        devices.forEach(d => {
            const name = (d.name || d.ip || 'Unknown').substring(0, 24);
            console.log(`${name.padEnd(25)} ${(d.ip || 'N/A').padEnd(18)} ${(d.mac || 'N/A').padEnd(18)}`);
        });
        console.log("");
    }
}

// Command: device <ip> block <on|off>
// Demonstrates the safest way to manage firewall policies programmatically.
async function toggleDeviceBlock(targetIp, state) {
    if (!currentGid) return console.log("% Error: No box selected.");
    
    // STEP 1: Translate the IP address into a MAC address. 
    // Firewalla rules are primarily bound to MAC addresses, not IPs.
    const devices = await apiRequest(`/devices?box_gid=${currentGid}`);
    const dev = devices ? devices.find(d => d.ip === targetIp) : null;
    if (!dev) return console.log(`% Error: Device ${targetIp} not found.`);

    // STEP 2: Fetch all rules for this specific box.
    const rulesData = await apiRequest(`/rules?query=box.id:${currentGid}`);
    
    // STEP 3: Search the active rules to find one that is a "block" rule AND targets our device's MAC.
    // (Note: Kept backwards compatible for older Node.js versions running on Firewalla hardware).
    let rule = null;
    if (rulesData && rulesData.results) {
        rule = rulesData.results.find(r => r.action === 'block' && JSON.stringify(r).includes(dev.mac));
    }

    if (!rule) {
        console.log(`% Error: No existing block rule found for ${targetIp}.`);
        console.log(`% Tip: Create a paused block rule in the Firewalla App first, then toggle it here.`);
        return;
    }

    // STEP 4: Trigger the action. "block on" means we resume the rule. "block off" means we pause it.
    const action = state === 'on' ? 'resume' : 'pause';
    console.log(`% Executing: POST ${BASE_URL}/rules/${rule.id}/${action}`);
    
    if (await apiRequest(`/rules/${rule.id}/${action}`, 'POST')) {
        console.log(`% Success: Block rule for ${targetIp} is now ${state.toUpperCase()}.`);
    }
}

/**
 * --- 4. CLI INTERFACE ENGINE ---
 * Creates the interactive terminal loop.
 */
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask() {
    // Dynamic Prompting: If a box is selected, inject its ID into the prompt line.
    const prompt = `${hostname}${currentGid ? `(box:${currentGid.substring(0, 8)}...)` : ""}# `;
    
    rl.question(prompt, async (input) => {
        const line = input.trim();
        if (!line) return ask(); // Ignore empty 'Enters'
        
        const parts = line.split(/\s+/);
        const cmd = parts[0].toLowerCase();

        if (cmd === 'exit' || cmd === 'quit') process.exit(0);

        // --- COMMAND ROUTER ---
        if (line === '?') {
            console.log("\nAvailable Commands:");
            console.log(`  show inventory           List all boxes`);
            console.log(`  show version             Display hardware/OS details`);
            console.log(`  box <gid>                Select box context`);
            console.log(`  show device br           List devices`);
            console.log(`  device <ip> block <on|off> Toggle access rule\n`);
        } 
        else if (line === 'show inventory') await showInventory();
        else if (line === 'show version') await showVersion();
        else if (cmd === 'box') {
            // Locks the global context variable
            currentGid = parts[1];
            console.log(`% Context set to ${currentGid}`);
        } 
        else if (line === 'show device br') await showDeviceBrief();
        else if (cmd === 'device' && parts[2] === 'block') {
            await toggleDeviceBlock(parts[1], parts[3]);
        }
        else if (line !== "") {
            console.log("% Unrecognized command.");
        }
        
        // Recursively call ask() to keep the terminal alive
        ask();
    });
}

// Boot up the CLI
console.log(`\n--- Firewalla MSP CLI Example ---`);
console.log("Type '?' for help.\n");
ask();
