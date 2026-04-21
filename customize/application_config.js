// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/*
 * Saito CryptPad — application config overrides
 *
 * DUAL-PATH MODE: Standard username/password login is intentionally kept active.
 * Saito wallet login is offered as an additional option alongside it.
 *
 * TODO (prod hardening): Once Saito auth is stable and tested, disable standard
 * registration to make this a Saito-only instance:
 *   AppConfig.disableRegistration = true;
 *   AppConfig.hideLoginRegister = true;  // hides password fields from login page
 * Keep this dual-path for development and theming work.
 */

(() => {
const factory = (AppConfig) => {

    // Saito wallet login is added as an extra option — standard login unchanged.
    // Set to true when ready to go Saito-only in production.
    AppConfig.saitoAuthOnly = false;

    // TODO (prod): set to true to disable standard account registration
    // AppConfig.disableRegistration = true;

    return AppConfig;
};

if (typeof(module) !== 'undefined' && module.exports) {
    module.exports = factory(
        require('../www/common/application_config_internal.js')
    );
} else if ((typeof(define) !== 'undefined' && define !== null) && (define.amd !== null)) {
    define(['/common/application_config_internal.js'], factory);
}

})();
