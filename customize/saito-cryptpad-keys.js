// saito-cryptpad-keys.js
// Derives CryptPad-compatible entropy from a Saito Ed25519 wallet keypair.
//
// CryptPad's login flow uses scrypt to derive 192 bytes of entropy from
// username + password, then allocateBytes() slices those 192 bytes into
// encryption seeds, channel seeds, curve keys, and signing keys.
//
// For Saito wallet auth, we bypass scrypt and instead derive 192 bytes
// deterministically from the Saito private key using repeated hashing.
// Same wallet → same 192 bytes → same CryptPad identity. Always.
//
// IMPORTANT: Key rotation — if a user rotates their Saito wallet keypair,
// they get a new CryptPad identity and will need to re-share documents.

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
     * Derive 192 bytes of deterministic entropy from a Saito private key.
     * This replaces scrypt in the CryptPad login flow.
     *
     * Uses libsodium's crypto_generichash (BLAKE2b) to expand the key material
     * into the required number of bytes via a simple KDF chain:
     *   block_0 = BLAKE2b-512(privkey || "saito-cryptpad-v1" || 0x00)
     *   block_1 = BLAKE2b-512(privkey || "saito-cryptpad-v1" || 0x01)
     *   block_2 = BLAKE2b-512(privkey || "saito-cryptpad-v1" || 0x02)
     *   block_3 = BLAKE2b-512(privkey || "saito-cryptpad-v1" || 0x03)
     *   result  = (block_0 || block_1 || block_2 || block_3)[0..192]
     *
     * Each block is 64 bytes (BLAKE2b-512), so 4 blocks = 256 bytes, truncated to 192.
     *
     * @param {Uint8Array} saitoPrivateKey - 64-byte Ed25519 secret key (seed || publicKey)
     * @returns {Uint8Array} - 192 bytes of deterministic entropy
     */
    function deriveEntropy(saitoPrivateKey) {
        if (!saitoPrivateKey || saitoPrivateKey.length !== 64) {
            throw new Error('SaitoCryptPadKeys: expected 64-byte Ed25519 secret key');
        }

        if (typeof sodium === 'undefined') {
            throw new Error('SaitoCryptPadKeys: libsodium-wrappers not loaded');
        }

        var DOMAIN = new Uint8Array([
            // "saito-cryptpad-v1" as bytes
            0x73, 0x61, 0x69, 0x74, 0x6f, 0x2d, 0x63, 0x72,
            0x79, 0x70, 0x74, 0x70, 0x61, 0x64, 0x2d, 0x76, 0x31
        ]);

        var REQUIRED = 192;
        var BLOCK_SIZE = 64; // BLAKE2b-512 output
        var blocks = Math.ceil(REQUIRED / BLOCK_SIZE);
        var output = new Uint8Array(blocks * BLOCK_SIZE);

        for (var i = 0; i < blocks; i++) {
            // input = privkey || domain || counter_byte
            var input = new Uint8Array(saitoPrivateKey.length + DOMAIN.length + 1);
            input.set(saitoPrivateKey, 0);
            input.set(DOMAIN, saitoPrivateKey.length);
            input[input.length - 1] = i;

            var hash = sodium.crypto_generichash(BLOCK_SIZE, input);
            output.set(hash, i * BLOCK_SIZE);
        }

        return output.slice(0, REQUIRED);
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
        var keyStr;
        if (typeof saitoPublicKey === 'string') {
            keyStr = saitoPublicKey.slice(0, 16);
        } else {
            // Convert bytes to hex for stable string representation
            keyStr = Array.from(saitoPublicKey.slice(0, 8))
                .map(function (b) { return b.toString(16).padStart(2, '0'); })
                .join('');
        }
        return 'saito_' + keyStr;
    }

    return {
        deriveEntropy: deriveEntropy,
        deterministicUsername: deterministicUsername,
    };
}));
