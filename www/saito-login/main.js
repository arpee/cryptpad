// Saito wallet login — iframe-safe (no window.top check)
//
// This page is loaded inside the Saito Docs module iframe via the relay page.
// It reads wallet keys from sessionStorage, derives CryptPad entropy,
// and performs loginOrRegister directly.
//
// Flow: saito-auth.html writes keys → redirects here → we login/register → redirect to /drive/

define([
    '/api/config',
    '/customize/saito-cryptpad-keys.js',
    '/common/common-login.js',
    '/common/outer/local-store.js',
    '/common/common-credential.js',

    // Ensure tweetnacl is loaded (provides nacl.hash for SHA-512)
    '/components/tweetnacl/nacl-fast.min.js',
], function (Config, SaitoKeys, Login, LocalStore, Cred) {

    var msg = document.getElementById('msg');
    var spinner = document.getElementById('spinner');

    function setStatus(text, isError) {
        msg.textContent = text;
        if (isError) {
            msg.classList.add('error');
            if (spinner) spinner.style.display = 'none';
        }
    }

    // If already logged in, go straight to drive
    if (LocalStore.isLoggedIn()) {
        setStatus('Already logged in — loading…');
        window.location.replace('/drive/');
        return;
    }

    // Read keys from sessionStorage (written by saito-auth.html relay)
    var stored = sessionStorage.getItem('SAITO_AUTH_KEYS');
    if (!stored) {
        setStatus('No wallet keys found — redirecting…');
        setTimeout(function() { window.location.replace('/'); }, 1500);
        return;
    }

    var keys;
    try {
        keys = JSON.parse(stored);
    } catch(e) {
        setStatus('Invalid key data — redirecting…', true);
        setTimeout(function() { window.location.replace('/'); }, 1500);
        return;
    }

    if (!keys || !keys.signingKey) {
        setStatus('Missing signing key — redirecting…', true);
        setTimeout(function() { window.location.replace('/'); }, 1500);
        return;
    }

    setStatus('Deriving keys…');

    try {
        // Convert plain array back to Uint8Array
        var privBytes = new Uint8Array(keys.signingKey);
        if (privBytes.length !== 64) {
            setStatus('Invalid key length (' + privBytes.length + ')', true);
            return;
        }

        // Derive 192 bytes of deterministic entropy (SHA-512 KDF via nacl.hash)
        var entropy = SaitoKeys.deriveEntropy(privBytes);
        var username = SaitoKeys.deterministicUsername(keys.publicKey);

        // Set entropy for common-credential.js hook
        window.SAITO_AUTH_BYTES = entropy;

        // Clear sessionStorage
        sessionStorage.removeItem('SAITO_AUTH_KEYS');

        setStatus('Signing in…');

        // Try login first (most common case — account already exists)
        Login.loginOrRegister({
            uname: username,
            passwd: 'saito-wallet-auth',
            isRegister: false,
        }, function(err, result) {
            if (!err && result) {
                // Login success
                setStatus('Welcome back!');
                window.location.replace('/drive/');
                return;
            }

            // If no such user, register
            if (err === 'NO_SUCH_USER') {
                setStatus('Creating account…');

                // Re-set SAITO_AUTH_BYTES (consumed by first attempt)
                window.SAITO_AUTH_BYTES = entropy;

                Login.loginOrRegister({
                    uname: username,
                    passwd: 'saito-wallet-auth',
                    isRegister: true,
                }, function(err2, result2) {
                    if (err2) {
                        setStatus('Registration failed: ' + err2, true);
                        return;
                    }
                    setStatus('Account created — loading…');
                    window.location.replace('/drive/');
                });
                return;
            }

            // Some other error
            setStatus('Auth failed: ' + (err || 'unknown error'), true);
        });

    } catch(e) {
        setStatus('Error: ' + (e.message || e), true);
    }
});
