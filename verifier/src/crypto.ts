import crypto from 'crypto';

function loadAESKey(): Buffer {
    const hexKey = process.env.AES_SECRET_KEY;
    if (!hexKey) {
        throw new Error(
            '[FATAL] AES_SECRET_KEY environment variable is not set.\n' +
            'Generate one with: openssl rand -hex 32\n' +
            'Then export it: export AES_SECRET_KEY=<your-64-hex-char-key>'
        );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) {
        throw new Error(
            '[FATAL] AES_SECRET_KEY must be exactly 64 hex characters (32 bytes).\n' +
            'Generate one with: openssl rand -hex 32'
        );
    }
    return Buffer.from(hexKey, 'hex');
}

const AES_KEY = loadAESKey();

export function encryptAES(payload: object): string {
    const iv = crypto.randomBytes(12); // 96-bit nonce for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
    
    const jsonStr = JSON.stringify(payload);
    let encrypted = cipher.update(jsonStr, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag(); // 16 bytes
    
    // Format: base64(iv) + '.' + base64(ciphertext) + '.' + base64(authTag)
    return `${iv.toString('base64')}.${encrypted}.${authTag.toString('base64')}`;
}

export function decryptAES(encryptedPayload: string): any {
    const parts = encryptedPayload.split('.');
    if (parts.length !== 3) throw new Error('Invalid encrypted payload format');
    
    const iv = Buffer.from(parts[0], 'base64');
    const ciphertext = parts[1];
    const authTag = Buffer.from(parts[2], 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}
