import axios from 'axios';

/**
 * Sends telemetry lead events from web/mobile wrapper to the backend CRM.
 * @param {Object} params
 * @param {string} params.serviceId - e.g. 'pvt-ltd-registration'
 * @param {string} params.serviceName - e.g. 'Private Limited Company'
 * @param {string} [params.packageName] - e.g. 'Standard Incorporation'
 * @param {number} [params.price] - e.g. 6499
 * @param {'PAGE_VIEW' | 'PACKAGE_CLICK'} [params.category='PAGE_VIEW']
 * @param {'web' | 'ios' | 'android'} [params.source='web']
 */
export const trackLeadEvent = async ({
    serviceId,
    serviceName,
    packageName = null,
    price = 0,
    category = 'PAGE_VIEW',
    source = 'web'
}) => {
    try {
        const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
        const token = userInfo?.token;
        const headers = token ? { Authorization: `Bearer ${token}` } : {};

        await axios.post(
            '/api/leads/telemetry',
            {
                customerId: userInfo?._id || null,
                customerName: userInfo?.name || 'Guest Prospect',
                email: userInfo?.email || null,
                phone: userInfo?.phone || null,
                serviceId,
                serviceName,
                packageName,
                price: Number(price) || 0,
                category,
                source,
                deviceInfo: typeof navigator !== 'undefined' ? navigator.userAgent : ''
            },
            { headers }
        );
    } catch (err) {
        console.debug('Lead telemetry background sync:', err?.message);
    }
};

export const trackLead = trackLeadEvent;
