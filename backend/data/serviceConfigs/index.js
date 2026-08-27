import { privateLimitedConfig } from './privateLimited.js';
import { publicLimitedConfig } from './publicLimited.js';
import { llpConfig } from './llp.js';
import { partnershipConfig } from './partnership.js';
import { proprietorshipConfig } from './proprietorship.js';
import { section8Config } from './section8.js';
import { onePersonCompanyConfig } from './onePersonCompany.js';
import { societyTrustConfig } from './societyTrust.js';
import { EXTENDED_SERVICE_CONFIGS } from './extendedConfigs.js';

export const ALL_SERVICE_CONFIGS = {
    'private-limited': privateLimitedConfig,
    'pvt-ltd-registration': privateLimitedConfig,
    'public-limited-company': publicLimitedConfig,
    'llp-registration': llpConfig,
    'partnership-firm-registration': partnershipConfig,
    'partnership-firm': partnershipConfig,
    'proprietorship-setup': proprietorshipConfig,
    'sole-proprietorship': proprietorshipConfig,
    'section-8-company': section8Config,
    'section-8-company-registration': section8Config,
    'one-person-company': onePersonCompanyConfig,
    'opc-registration': onePersonCompanyConfig,
    'society-trust-registration': societyTrustConfig,
    'trust-registration': societyTrustConfig,
    'society-registration': societyTrustConfig,
    ...EXTENDED_SERVICE_CONFIGS
};

export {
    privateLimitedConfig,
    publicLimitedConfig,
    llpConfig,
    partnershipConfig,
    proprietorshipConfig,
    section8Config,
    onePersonCompanyConfig,
    societyTrustConfig,
    EXTENDED_SERVICE_CONFIGS
};
