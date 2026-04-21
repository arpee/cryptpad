// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Saito CryptPad — login page override
//
// DUAL-PATH: Adds a "Sign in with Saito Wallet" button alongside the existing
// username/password form. Standard login is fully preserved.
//
// TODO (prod hardening): When going Saito-only, set AppConfig.saitoAuthOnly = true
// in customize/application_config.js. That flag is checked below to hide the
// standard form if desired. Do not remove the standard form code — just hide it.

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
     * Attempt to get the Saito wallet from the page context.
     * This will be available when CryptPad is loaded inside a Saito module
     * iframe/redirect with the wallet injected into the parent frame.
     *
     * Returns null if no Saito wallet is available (standard login path).
     */
    function getSaitoWallet() {
        try {
            // When loaded via Saito module redirect with sessionStorage handoff
            const stored = sessionStorage.getItem('SAITO_AUTH_KEYS');
            if (stored) { return JSON.parse(stored); }

            // When loaded in an iframe with parent wallet access
            if (window.parent && window.parent.saito && window.parent.saito.wallet) {
                return window.parent.saito.wallet;
            }

            // Direct wallet access if available in this frame
            if (window.saito && window.saito.wallet) {
                return window.saito.wallet;
            }
        } catch (e) {
            console.warn('SaitoLogin: wallet access failed', e);
        }
        return null;
    }

    /**
     * Perform Saito wallet login:
     * 1. Derive CryptPad keypairs from Saito private key
     * 2. Set window.SAITO_AUTH_KEYS so the core login.js hook picks them up
     * 3. Trigger the standard CryptPad login flow
     */
    async function saitoLogin(onSuccess, onError) {
        try {
            const wallet = getSaitoWallet();
            if (!wallet) {
                onError('No Saito wallet found. Please open CryptPad from your Saito application.');
                return;
            }

            // Derive keypairs — requires libsodium to be loaded
            // libsodium-wrappers is loaded by CryptPad's own bundle; wait for ready
            if (typeof sodium !== 'undefined' && sodium.ready) {
                await sodium.ready;
            }

            const privateKey = wallet.privateKey || wallet.secretKey;
            if (!privateKey) {
                onError('Could not access wallet private key.');
                return;
            }

            const keys = SaitoKeys.deriveKeypairs(
                typeof privateKey === 'string'
                    ? Uint8Array.from(Buffer.from(privateKey, 'hex'))
                    : privateKey
            );
            const username = SaitoKeys.deterministicUsername(
                wallet.publicKey || keys.sign.publicKey
            );

            // Set the keys where the core login.js hook will find them
            window.SAITO_AUTH_KEYS = keys;

            // Clear sessionStorage handoff token now that keys are loaded
            sessionStorage.removeItem('SAITO_AUTH_KEYS');

            onSuccess(username, keys);
        } catch (err) {
            console.error('SaitoLogin error:', err);
            onError('Wallet login failed: ' + (err.message || err));
        }
    }

    // -------------------------------------------------------------------------
    // UI — inject Saito login button above the standard form
    // -------------------------------------------------------------------------

    function injectSaitoButton() {
        const $loginForm = $('#login-form, .cp-login-form, form.login').first();
        if (!$loginForm.length) {
            // DOM not ready yet — retry shortly
            setTimeout(injectSaitoButton, 200);
            return;
        }

        const $btn = $('<button>', {
            id: 'saito-wallet-login',
            class: 'btn btn-primary saito-login-btn',
            text: 'Sign in with Saito Wallet',
            type: 'button',
        }).css({
            width: '100%',
            marginBottom: '12px',
        });

        const $status = $('<div>', {
            id: 'saito-login-status',
            class: 'saito-login-status',
        }).css({ marginBottom: '8px', display: 'none' });

        const $divider = $('<div>', { class: 'saito-login-divider' })
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
                function (username /*, keys */) {
                    $status.text('Wallet connected. Signing in…').show();
                    // Standard CryptPad login flow will pick up window.SAITO_AUTH_KEYS
                    // Trigger the existing login submit with the derived username
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
        // standard username/password fields so only wallet login is available:
        // if (AppConfig.saitoAuthOnly) {
        //     $loginForm.find('input[name="username"], input[name="password"], button[type="submit"]')
        //         .closest('.form-group, .cp-login-field').hide();
        //     $divider.hide();
        // }
    }

    // Inject the button once the DOM is ready
    $(function () { injectSaitoButton(); });

    // Re-export everything from the standard login module unchanged
    return StandardLogin;
});
