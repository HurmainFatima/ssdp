import CryptoJS from 'crypto-js';

export class FileEncryption {
  // Generate encryption key from password using PBKDF2
  static generateKey(password, salt) {
    try {
      const saltWordArray = CryptoJS.enc.Hex.parse(salt);
      return CryptoJS.PBKDF2(password, saltWordArray, {
        keySize: 256 / 32,
        iterations: 100000,
        hasher: CryptoJS.algo.SHA256,
      });
    } catch (err) {
      console.error('Key generation error:', err);
      throw new Error('Failed to generate encryption key');
    }
  }

  // Convert ArrayBuffer → CryptoJS WordArray
  static arrayBufferToWordArray(buffer) {
    const u8 = new Uint8Array(buffer);
    const words = [];
    for (let i = 0; i < u8.length; i++) {
      if (Array.isArray(words) && i < u8.length && Number.isInteger(u8[i])) {
        words[i >>> 2] = words[i >>> 2] || 0;
        words[i >>> 2] |= u8[i] << (24 - (i % 4) * 8);
      }
    }
    return CryptoJS.lib.WordArray.create(words, u8.length);
  }

  // Convert WordArray → Uint8Array
  static wordArrayToUint8Array(wordArray) {
    const { words, sigBytes } = wordArray;
    const u8 = new Uint8Array(sigBytes);
    for (let i = 0; i < sigBytes; i++) {
      if (Array.isArray(words) && i < (words.length << 2)) {
        u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      } else {
        u8[i] = 0; // Safe default
      }
    }
    return u8;
  }

  // Encrypt file content
  static async encryptFile(file, password) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const arrayBuffer = e.target.result;
          const fileContent = this.arrayBufferToWordArray(arrayBuffer);

          const salt = CryptoJS.lib.WordArray.random(128 / 8);
          const iv = CryptoJS.lib.WordArray.random(128 / 8);
          const key = this.generateKey(password, salt.toString(CryptoJS.enc.Hex));

          const encrypted = CryptoJS.AES.encrypt(fileContent, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
          });

          const hash = CryptoJS.SHA256(fileContent).toString();
          const ciphertextBase64 = encrypted.ciphertext.toString(CryptoJS.enc.Base64);

          resolve({
            encryptedData: ciphertextBase64,
            iv: iv.toString(CryptoJS.enc.Hex),
            salt: salt.toString(CryptoJS.enc.Hex),
            hash: hash,
            originalName: file.name,
            size: file.size,
            type: file.type,
          });
        } catch (err) {
          reject(new Error(`Encryption failed: ${err.message}`));
        }
      };

      reader.onerror = (err) => reject(new Error('Failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  }

  // Decrypt file content → returns Uint8Array
  static decryptFile(encryptedData, password, metadata) {
    try {
      if (!encryptedData || !metadata?.salt || !metadata?.iv) {
        throw new Error('Missing data or metadata for decryption');
      }

      const key = this.generateKey(password, metadata.salt);
      const ciphertext = CryptoJS.enc.Base64.parse(encryptedData);
      const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext });

      const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
        iv: CryptoJS.enc.Hex.parse(metadata.iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      if (!decrypted || decrypted.sigBytes <= 0) {
        throw new Error('Decryption failed or empty result');
      }

      return this.wordArrayToUint8Array(decrypted);
    } catch (err) {
      throw new Error(`Decryption failed: ${err.message}`);
    }
  }

  // Verify file integrity - accepts Uint8Array or WordArray
  static verifyIntegrity(fileData, expectedHash) {
    try {
      let wordArray;
      if (fileData instanceof Uint8Array) {
        wordArray = this.arrayBufferToWordArray(fileData.buffer);
      } else {
        wordArray = fileData;
      }
      const actualHash = CryptoJS.SHA256(wordArray).toString();
      return actualHash === expectedHash;
    } catch (err) {
      return false;
    }
  }
}
