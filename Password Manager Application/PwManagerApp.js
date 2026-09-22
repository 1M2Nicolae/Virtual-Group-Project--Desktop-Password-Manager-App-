const fs = require('fs'); // file system module that allows to read and write files
const path = require('path'); // loads path module to handle file locations and directories
const crypto = require('crypto'); // security module used for hashing and encryption
const readline = require('readline');
const VAULT_FILE = path.join(__dirname, 'password_vault.enc');
const SETTINGS_FILE = path.join(__dirname, 'user_settings.json');
// create a interface between terminal and application
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (question) => new Promise(resolve => rl.question(question, resolve));
//  Security Functions Section 
// This function hashes the master password for login verification
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}
// This is creating a AES-256 encryption key
function createKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}
// Encrypting the vault data
function encryptData(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), data: encrypted };
}
// Decrypts data vault
function decryptData(encrypted, key) {
    const iv = Buffer.from(encrypted.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
// Using backup function to create a backup before saving changes
function backupVault() {
    if (fs.existsSync(VAULT_FILE)) {
        fs.copyFileSync(VAULT_FILE, `${VAULT_FILE}.backup`);
    }
}
// --- First Time initializing the app and setup a master pw ---
async function setupApp() {
    if (fs.existsSync(SETTINGS_FILE)) return;
    console.log('\n=== PASSWORD MANAGER SETUP ===');
    const masterPassword = await ask('Create Master Password: ');
    const salt = crypto.randomBytes(16).toString('hex');
    const settings = {
        passwordHash: hashPassword(masterPassword),
        salt
    };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
    // Creates an empty encrypted vault
    const key = createKey(masterPassword, salt);
    const emptyVault = encryptData(JSON.stringify([]), key);
    fs.writeFileSync(VAULT_FILE, JSON.stringify(emptyVault, null, 2));
    console.log('Setup complete.\n');
}
// --- Login section ---
async function login() {
    const settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    console.log('\n=== SECURE LOGIN ===');
    const password = await ask('Enter Master Password: ');
    if (hashPassword(password) !== settings.passwordHash) {
        console.log('Incorrect password.');
        return null;
    }
    console.log('Login successful.');
    return createKey(password, settings.salt);
}
// Vault Storage 
function loadVault(key) {
    if (!fs.existsSync(VAULT_FILE)) return [];
    try {
        const stored = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
        return JSON.parse(decryptData(stored, key));
    } catch (error) {
        console.log('Unable to open vault.');
        return [];
    }
}
function saveVault(vault, key) {
    backupVault();
    const encrypted = encryptData(JSON.stringify(vault), key);
    fs.writeFileSync(VAULT_FILE, JSON.stringify(encrypted, null, 2));
}
// Interaction section ( Displayng My Menu and CRUD operations)
async function runSession(key) {
    const vault = loadVault(key);
    let active = true;
    while (active) {
        console.log('\n--- Password Manager Dashboard --- \n-------(Birmingham Group) -------');
        console.log('1. View Credentials (Read)');
        console.log('2. Add Credential (Create)');
        console.log('3. Update Credential (Update)');
        console.log('4. Delete Credential (Delete)');
        console.log('5. Lock Vault & Logout');
        const choice = await ask('Select an option (1-5): ');
        switch (choice.trim()) {
            // Case section - Displaying all stored credentials
            case '1':
                console.log('\n--- View Credentials ---');
                if (vault.length === 0) {
                    console.log('No credentials saved yet.');
                } else {
                    vault.forEach((item, index) => {
                        console.log(
                            `[${index + 1}] Service: ${item.website} | ` +
                            `Username: ${item.username} | ` +
                            `Password: ${item.password}`
                        );
                    });
                }
                break;
            // CREATE: Adds a new credential to the vault
            case '2':
                console.log('\n--- Add Credential ---');
                const website = await ask('Website / Service: ');
                const username = await ask('Username / Email: ');
                const password = await ask('Password: ');
                vault.push({ website, username, password });
                saveVault(vault, key);
                console.log('Credential added successfully.');
                break;
            // UPDATE: Changes an existing credential
            case '3':
                console.log('\n--- Update Credential ---');
                if (vault.length === 0) {
                    console.log('Vault is empty.');
                    break;
                }
                vault.forEach((item, index) => {
                    console.log(`[${index + 1}] ${item.website} (${item.username})`);
                });
                const updateIdx = await ask('Enter entry number to update: ');
                const updateIndex = parseInt(updateIdx) - 1;
                if (updateIndex >= 0 && updateIndex < vault.length) {
                    const newWebsite = await ask(
                        `Website (${vault[updateIndex].website}): `
                    );
                    const newUsername = await ask(
                        `Username (${vault[updateIndex].username}): `
                    );
                    const newPassword = await ask('New Password: ');
                    if (newWebsite.trim()) vault[updateIndex].website = newWebsite;
                    if (newUsername.trim()) vault[updateIndex].username = newUsername;
                    if (newPassword.trim()) vault[updateIndex].password = newPassword;
                    saveVault(vault, key);
                    console.log('Credential updated successfully.');
                } else {
                    console.log('Invalid index.');
                }
                break;
            // DELETE: Removes a credential from the vault
            case '4':
                console.log('\n--- Delete Credential ---');
                if (vault.length === 0) {
                    console.log('Vault is empty.');
                    break;
                }
                vault.forEach((item, index) => {
                    console.log(`[${index + 1}] ${item.website} (${item.username})`);
                });
                const delIdx = await ask('Enter entry number to delete: ');
                const idx = parseInt(delIdx) - 1;
                if (idx >= 0 && idx < vault.length) {
                    const removed = vault.splice(idx, 1);
                    saveVault(vault, key);
                    console.log(`Removed entry for ${removed[0].website}.`);
                } else {
                    console.log('Invalid index.');
                }
                break;
            // Locks the vault and ends the active session
            case '5':
                console.log('Vault locked. Logged out.');
                active = false;
                break;
            default:
                console.log('Invalid option.');
        }
    }
}
// --- Application Start ---
async function main() {
    await setupApp();
    const key = await login();
    if (key) await runSession(key);
    rl.close();
}
main();