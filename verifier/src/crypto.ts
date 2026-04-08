import crypto from 'crypto';

const AES_KEY_STRING = process.env.AES_SECRET_KEY || 'pos-captcha-secret-key-32-bytes!';
const AES_KEY = Buffer.from(AES_KEY_STRING, 'utf8');

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
