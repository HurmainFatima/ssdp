// services/encryption.js - FINAL WORKING VERSION
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
      u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
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

          // Generate random salt and IV
          const salt = CryptoJS.lib.WordArray.random(128 / 8);
          const iv = CryptoJS.lib.WordArray.random(128 / 8);

          const key = this.generateKey(password, salt.toString(CryptoJS.enc.Hex));

          console.log('🔐 Encryption Debug:', {
            passwordLength: password.length,
            saltHex: salt.toString(CryptoJS.enc.Hex),
            ivHex: iv.toString(CryptoJS.enc.Hex),
            fileSize: file.size,
            fileName: file.name
          });

          const encrypted = CryptoJS.AES.encrypt(fileContent, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
          });

          const hash = CryptoJS.SHA256(fileContent).toString();

          // Extract ciphertext as base64
          const ciphertextBase64 = encrypted.ciphertext.toString(CryptoJS.enc.Base64);

          console.log('✅ Encryption complete:', {
            ciphertextLength: ciphertextBase64.length,
            hashLength: hash.length
          });

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
          console.error('Encryption error:', err);
          reject(new Error(`Encryption failed: ${err.message}`));
        }
      };

      reader.onerror = (err) => {
        console.error('File read error:', err);
        reject(new Error('Failed to read file'));
      };
      
      reader.readAsArrayBuffer(file);
    });
  }

  // Decrypt file content → returns Uint8Array
  static decryptFile(encryptedData, password, metadata) {
    try {
      console.log('🔓 Decryption Debug:', {
        passwordLength: password.length,
        encryptedDataLength: encryptedData.length,
        metadataIV: metadata.iv,
        metadataSalt: metadata.salt,
        expectedHash: metadata.hash
      });

      const salt = metadata.salt;
      const iv = metadata.iv;

      // Validate inputs
      if (!salt || !iv) {
        throw new Error('Missing salt or IV in metadata');
      }

      if (!encryptedData) {
        throw new Error('No encrypted data provided');
      }

      const key = this.generateKey(password, salt);

      // Parse the base64 ciphertext
      let ciphertext;
      try {
        ciphertext = CryptoJS.enc.Base64.parse(encryptedData);
        console.log('📦 Parsed ciphertext words:', ciphertext.words.length);
      } catch (err) {
        throw new Error(`Failed to parse base64: ${err.message}`);
      }
      
      // Create CipherParams object
      const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertext
      });

      // Decrypt
      let decrypted;
      try {
        decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
          iv: CryptoJS.enc.Hex.parse(iv),
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        });
      } catch (err) {
        throw new Error(`AES decryption failed: ${err.message}`);
      }

      console.log('📝 Decrypted sigBytes:', decrypted.sigBytes);

      // Check if decryption produced valid data
      if (!decrypted || decrypted.sigBytes <= 0) {
        throw new Error('Decryption produced empty result - likely wrong password');
      }

      // Convert to Uint8Array
      const decryptedArray = this.wordArrayToUint8Array(decrypted);
      
      console.log('✅ Decryption complete:', {
        decryptedSize: decryptedArray.length
      });

      return decryptedArray;
    } catch (err) {
      console.error('❌ Decryption error:', err);
      throw new Error(`Decryption failed: ${err.message}`);
    }
  }

  // Verify file integrity - accepts Uint8Array or WordArray
  static verifyIntegrity(fileData, expectedHash) {
    try {
      let wordArray;
      if (fileData instanceof Uint8Array) {
        // Convert Uint8Array to WordArray for hashing
        wordArray = this.arrayBufferToWordArray(fileData.buffer);
      } else {
        wordArray = fileData;
      }
      
      const actualHash = CryptoJS.SHA256(wordArray).toString();
      const match = actualHash === expectedHash;
      
      console.log('🔍 Integrity check:', {
        expectedHash: expectedHash.substring(0, 16) + '...',
        actualHash: actualHash.substring(0, 16) + '...',
        match: match
      });
      
      return match;
    } catch (err) {
      console.error('Integrity check error:', err);
      return false;
    }
  }
}
