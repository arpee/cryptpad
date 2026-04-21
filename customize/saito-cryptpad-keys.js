// saito-cryptpad-keys.js
// Derives CryptPad-compatible entropy from a Saito Ed25519 wallet keypair.
//
// CryptPad's login flow uses scrypt to derive 192 bytes of entropy from
// username + password, then allocateBytes() slices those 192 bytes into
// encryption seeds, channel seeds, curve keys, and signing keys.
//
// For Saito wallet auth, we bypass scrypt and instead derive 192 bytes
// deterministically from the Saito private key using repeated SHA-512 hashing.
// Same wallet → same 192 bytes → same CryptPad identity. Always.
//
// Uses tweetnacl's nacl.hash (SHA-512) which is already bundled by CryptPad.
// No libsodium dependency.
//
// IMPORTANT: Key rotation — if a user rotates their Saito wallet keypair,
// they get a new CryptPad identity and will need to re-share documents.

/* global nacl */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.SaitoCryptPadKeys = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    // Domain separator to avoid collisions with other uses of the same key
    var DOMAIN_STR = 'saito-cryptpad-v1';

    function domainBytes() {
        var arr = new Uint8Array(DOMAIN_STR.length);
        for (var i = 0; i < DOMAIN_STR.length; i++) {
            arr[i] = DOMAIN_STR.charCodeAt(i);
        }
        return arr;
    }

    /**
     * Concatenate Uint8Arrays.
     */
    function concat() {
        var total = 0;
        for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
        var result = new Uint8Array(total);
        var offset = 0;
        for (var j = 0; j < arguments.length; j++) {
            result.set(arguments[j], offset);
            offset += arguments[j].length;
        }
        return result;
    }

    /**
     * Derive 192 bytes of deterministic entropy from a Saito private key.
     * This replaces scrypt in the CryptPad login flow.
     *
     * Uses nacl.hash (SHA-512, provided by tweetnacl) to expand the key material
     * into the required number of bytes via a simple KDF chain:
     *   block_0 = SHA-512(privkey || "saito-cryptpad-v1" || 0x00)
     *   block_1 = SHA-512(privkey || "saito-cryptpad-v1" || 0x01)
     *   block_2 = SHA-512(privkey || "saito-cryptpad-v1" || 0x02)
     *   result  = (block_0 || block_1 || block_2)[0..192]
     *
     * Each block is 64 bytes (SHA-512), so 3 blocks = 192 bytes exactly.
     *
     * @param {Uint8Array} saitoPrivateKey - 64-byte Ed25519 secret key (seed || publicKey)
     * @returns {Uint8Array} - 192 bytes of deterministic entropy
     */
    function deriveEntropy(saitoPrivateKey) {
        if (!saitoPrivateKey || (saitoPrivateKey.length !== 64 && saitoPrivateKey.length !== 32)) {
            throw new Error('SaitoCryptPadKeys: expected 32-byte seed or 64-byte Ed25519 secret key, got ' + (saitoPrivateKey ? saitoPrivateKey.length : 'null'));
        }

        // If 32-byte seed, expand to 64-byte key using nacl.sign.keyPair.fromSeed
        if (saitoPrivateKey.length === 32) {
            if (typeof nacl === 'undefined' || !nacl.sign) {
                throw new Error('SaitoCryptPadKeys: nacl.sign not available for seed expansion');
            }
            saitoPrivateKey = nacl.sign.keyPair.fromSeed(saitoPrivateKey).secretKey;
        }

        // Use tweetnacl's nacl.hash (SHA-512)
        var hashFn;
        if (typeof nacl !== 'undefined' && nacl.hash) {
            hashFn = nacl.hash;
        } else {
            throw new Error('SaitoCryptPadKeys: nacl.hash (SHA-512) not available');
        }

        var DOMAIN = domainBytes();
        var REQUIRED = 192;
        var BLOCK_SIZE = 64; // SHA-512 output
        var blocks = Math.ceil(REQUIRED / BLOCK_SIZE); // 3 blocks = 192 bytes exactly
        var output = new Uint8Array(blocks * BLOCK_SIZE);

        for (var i = 0; i < blocks; i++) {
            // input = privkey || domain || counter_byte
            var counter = new Uint8Array([i]);
            var input = concat(saitoPrivateKey, DOMAIN, counter);
            var hash = hashFn(input);
            output.set(hash, i * BLOCK_SIZE);
        }

        return output.slice(0, REQUIRED);
    }

    /**
     * Derive a stable, unique CryptPad username from a Saito public key.
     *
     * @param {Uint8Array|string} saitoPublicKey - 32-byte key or base58/hex string
     * @returns {string} username like "saito_3xK9mPqR7vB2nL4w"
     */
    function deterministicUsername(saitoPublicKey) {
        var keyStr;
        if (typeof saitoPublicKey === 'string') {
            keyStr = saitoPublicKey.slice(0, 16);
        } else {
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
