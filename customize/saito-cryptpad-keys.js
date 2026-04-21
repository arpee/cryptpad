// saito-cryptpad-keys.js
// Derives CryptPad-compatible keypairs from a Saito Ed25519 wallet keypair.
//
// CryptPad needs two keypairs per user:
//   - Signing keypair:    Ed25519  → direct reuse of Saito key
//   - Encryption keypair: Curve25519 → standard Ed25519→X25519 conversion (libsodium)
//
// This derivation is deterministic: same Saito wallet always produces the same
// CryptPad identity. The conversion is well-tested in production by Signal,
// Keybase, and others.
//
// IMPORTANT: Key rotation — if a user rotates their Saito wallet keypair, they
// get a new CryptPad identity and will need to re-share any documents they own.
// Document this clearly to users.

/* global sodium */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.SaitoCryptPadKeys = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    /**
     * Derive CryptPad signing + encryption keypairs from a Saito private key.
     *
     * @param {Uint8Array} saitoPrivateKey - 64-byte Ed25519 secret key (seed || publicKey)
     * @returns {{ sign: {secretKey, publicKey}, encrypt: {secretKey, publicKey} }}
     */
    function deriveKeypairs(saitoPrivateKey) {
        if (!saitoPrivateKey || saitoPrivateKey.length !== 64) {
            throw new Error('SaitoCryptPadKeys: expected 64-byte Ed25519 secret key');
        }

        // Signing: Ed25519 — direct reuse, same curve
        const signingSecret = saitoPrivateKey;              // 64 bytes
        const signingPublic = saitoPrivateKey.slice(32);    // last 32 bytes = public key

        // Encryption: convert Ed25519 → Curve25519 (X25519) via libsodium
        // sodium must be loaded and ready before calling this function
        if (typeof sodium === 'undefined') {
            throw new Error('SaitoCryptPadKeys: libsodium-wrappers not loaded');
        }
        const encryptSecret = sodium.crypto_sign_ed25519_sk_to_curve25519(signingSecret);
        const encryptPublic = sodium.crypto_sign_ed25519_pk_to_curve25519(signingPublic);

        return {
            sign:    { secretKey: signingSecret, publicKey: signingPublic },
            encrypt: { secretKey: encryptSecret, publicKey: encryptPublic },
        };
    }

    /**
     * Derive a stable, unique CryptPad username from a Saito public key.
     * CryptPad usernames are not the real identity (the keypair is) — this is
     * just a human-readable handle used internally.
     *
     * @param {Uint8Array|string} saitoPublicKey - 32-byte key or base58/hex string
     * @returns {string} username like "saito_3xK9mPqR7vB2nL4w"
     */
    function deterministicUsername(saitoPublicKey) {
        let keyStr;
        if (typeof saitoPublicKey === 'string') {
            keyStr = saitoPublicKey.slice(0, 16);
        } else {
            // Convert bytes to hex for stable string representation
            keyStr = Array.from(saitoPublicKey.slice(0, 8))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
        return 'saito_' + keyStr;
    }

    return {
        deriveKeypairs,
        deterministicUsername,
    };
}));
