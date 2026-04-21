// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Saito CryptPad — login page override
//
// DUAL-PATH: Adds a "Sign in with Saito Wallet" button alongside the existing
// username/password form. Standard login is fully preserved.
//
// Auth flow:
//   1. Saito module (docs.js) derives raw key material from the wallet
//   2. Redirects to saito-auth.html with keys in the URL fragment
//   3. Relay page writes keys to sessionStorage on cp.hda0.net origin
//   4. This login.js reads sessionStorage, derives 192 bytes of entropy
//      using BLAKE2b (via libsodium), sets window.SAITO_AUTH_BYTES
//   5. common-credential.js sees SAITO_AUTH_BYTES and bypasses scrypt
//   6. allocateBytes() slices the 192 bytes into CryptPad keypairs as normal
//
// TODO (prod hardening): When going Saito-only, set AppConfig.saitoAuthOnly = true
// in customize/application_config.js.

define([
    'jquery',
    '/customize/application_config.js',
    '/customize/saito-cryptpad-keys.js',
    '/customize.dist/login.js',  // inherit all standard login behaviour
], function ($, AppConfig, SaitoKeys, StandardLogin) {

    // -------------------------------------------------------------------------
    // Saito wallet login
    // -------------------------------------------------------------------------

    /**
     * Attempt to get the Saito wallet keys from available sources.
     * Returns the raw key payload or null.
     */
    function getSaitoWalletKeys() {
        try {
            // Primary path: sessionStorage handoff from saito-auth.html relay
            var stored = sessionStorage.getItem('SAITO_AUTH_KEYS');
            if (stored) {
                return JSON.parse(stored);
            }

            // Direct wallet access (when loaded inside Saito module iframe)
            var wallet = null;
            if (window.parent && window.parent.saito && window.parent.saito.wallet) {
                wallet = window.parent.saito.wallet;
            } else if (window.saito && window.saito.wallet) {
                wallet = window.saito.wallet;
            }
            if (wallet) {
                var pk = wallet.getPrivateKey ? wallet.getPrivateKey() : wallet.privateKey;
                if (pk) {
                    return {
                        signingKey: typeof pk === 'string'
                            ? Array.from(hexToUint8(pk))
                            : Array.from(pk),
                        publicKey: wallet.publicKey || wallet.getPublicKey()
                    };
                }
            }
        } catch (e) {
            console.warn('SaitoLogin: wallet access failed', e);
        }
        return null;
    }

    function hexToUint8(hex) {
        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    /**
     * Perform Saito wallet login:
     * 1. Read raw key material from sessionStorage or wallet
     * 2. Convert signingKey (plain array) back to Uint8Array
     * 3. Derive 192 bytes of entropy via SHA-512 KDF (nacl.hash)
     * 4. Set window.SAITO_AUTH_BYTES for common-credential.js hook
     * 5. Trigger the standard CryptPad login flow with a deterministic username
     */
    async function saitoLogin(onSuccess, onError) {
        try {
            var keys = getSaitoWalletKeys();
            if (!keys || !keys.signingKey) {
                onError('No Saito wallet found. Please open CryptPad from your Saito application.');
                return;
            }

            // Convert plain array back to Uint8Array (JSON roundtrip loses type)
            var privBytes = new Uint8Array(keys.signingKey);

            // Saito may return 32-byte seed or 64-byte full key (seed || pubkey)
            if (privBytes.length === 32 && window.nacl) {
                var kp = window.nacl.sign.keyPair.fromSeed(privBytes);
                privBytes = kp.secretKey; // 64 bytes
            } else if (privBytes.length !== 64) {
                onError('Invalid wallet key length (' + privBytes.length + ', expected 32 or 64).');
                return;
            }

            // Derive 192 bytes of deterministic entropy
            var entropy = SaitoKeys.deriveEntropy(privBytes);

            // Derive a stable username from the public key
            var username = SaitoKeys.deterministicUsername(keys.publicKey);

            // Set the entropy where common-credential.js will find it
            window.SAITO_AUTH_BYTES = entropy;

            // Clear sessionStorage handoff now that we've consumed it
            sessionStorage.removeItem('SAITO_AUTH_KEYS');

            onSuccess(username);
        } catch (err) {
            console.error('SaitoLogin error:', err);
            onError('Wallet login failed: ' + (err.message || err));
        }
    }

    // -------------------------------------------------------------------------
    // Auto-login: if sessionStorage has keys (from relay page), log in immediately
    // -------------------------------------------------------------------------

    function tryAutoLogin() {
        var stored = sessionStorage.getItem('SAITO_AUTH_KEYS');
        if (!stored) { return; }

        // Keys are present — trigger wallet login automatically
        saitoLogin(
            function (username) {
                // Fill the form and submit
                $('input[name="username"], #cp-login-username').val(username);
                $('input[name="password"], #cp-login-password').val('saito-wallet-auth');
                // Small delay to let the login page JS initialize
                setTimeout(function () {
                    $('button[type="submit"], #cp-login-submit').trigger('click');
                }, 200);
            },
            function (errMsg) {
                console.error('SaitoLogin auto-login failed:', errMsg);
                // Fall through to manual login
            }
        );
    }

    // -------------------------------------------------------------------------
    // UI — inject Saito login button above the standard form
    // -------------------------------------------------------------------------

    function injectSaitoButton() {
        var $loginForm = $('#login-form, .cp-login-form, form.login').first();
        if (!$loginForm.length) {
            // DOM not ready yet — retry shortly
            setTimeout(injectSaitoButton, 200);
            return;
        }

        var $btn = $('<button>', {
            id: 'saito-wallet-login',
            'class': 'btn btn-primary saito-login-btn',
            text: 'Sign in with Saito Wallet',
            type: 'button',
        }).css({
            width: '100%',
            marginBottom: '12px',
        });

        var $status = $('<div>', {
            id: 'saito-login-status',
            'class': 'saito-login-status',
        }).css({ marginBottom: '8px', display: 'none' });

        var $divider = $('<div>', { 'class': 'saito-login-divider' })
            .css({
                textAlign: 'center',
                margin: '8px 0 12px',
                color: '#888',
                fontSize: '0.85em',
            })
            .text('— or continue with username & password —');

        $btn.on('click', function () {
            $btn.prop('disabled', true).text('Connecting wallet…');
            $status.hide();

            saitoLogin(
                function (username) {
                    $status.text('Wallet connected. Signing in…').show();
                    $('input[name="username"], #cp-login-username').val(username);
                    $('input[name="password"], #cp-login-password').val('saito-wallet-auth');
                    $('button[type="submit"], #cp-login-submit').trigger('click');
                },
                function (errMsg) {
                    $status.text(errMsg).show();
                    $btn.prop('disabled', false).text('Sign in with Saito Wallet');
                }
            );
        });

        $loginForm.prepend($divider).prepend($btn).prepend($status);

        // TODO (prod hardening): if AppConfig.saitoAuthOnly === true, hide the
        // standard username/password fields:
        // if (AppConfig.saitoAuthOnly) {
        //     $loginForm.find('input[name="username"], input[name="password"], button[type="submit"]')
        //         .closest('.form-group, .cp-login-field').hide();
        //     $divider.hide();
        // }
    }

    // Run on DOM ready
    $(function () {
        injectSaitoButton();
        tryAutoLogin();
    });

    // Re-export everything from the standard login module unchanged
    return StandardLogin;
});
