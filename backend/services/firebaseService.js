import admin from 'firebase-admin';
import dotenv from 'dotenv';
import User from '../models/User.js';

dotenv.config();

let firebaseMessaging = null;

try {
    const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
    const serviceAccountPath = process.env.FIREBASE_CREDENTIALS_PATH;

    if (serviceAccountJson) {
        const credentials = JSON.parse(serviceAccountJson);
        admin.initializeApp({
            credential: admin.credential.cert(credentials),
        });
        firebaseMessaging = admin.messaging();
        console.log('Firebase Admin initialized successfully using env variable FIREBASE_SERVICE_ACCOUNT.');
    } else if (serviceAccountPath) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountPath),
        });
        firebaseMessaging = admin.messaging();
        console.log(`Firebase Admin initialized successfully using service account key file at ${serviceAccountPath}.`);
    } else {
        console.warn('Firebase Admin: No credentials provided in environment variables (FIREBASE_SERVICE_ACCOUNT or FIREBASE_CREDENTIALS_PATH). Firebase push notifications will be simulated (logged to console).');
    }
} catch (error) {
    console.error('Failed to initialize Firebase Admin SDK. Push notifications will be disabled or simulated:', error.message);
}

const convertApnsToFcmToken = async (apnsToken) => {
    try {
        const app = admin.app();
        const tokenObj = await app.options.credential.getAccessToken();
        const accessToken = tokenObj.access_token;
        
        for (const sandbox of [true, false]) {
            const res = await fetch('https://iid.googleapis.com/iid/v1:batchImport', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${accessToken}`,
                    'access_token_auth': 'true'
                },
                body: JSON.stringify({
                    application: 'com.sbr.vrherebms.ios',
                    sandbox: sandbox,
                    apns_tokens: [apnsToken]
                })
            });
            const json = await res.json();
            if (json.results && json.results[0] && json.results[0].registration_token) {
                const newFcm = json.results[0].registration_token;
                console.log(`Converted APNs token ${apnsToken} -> FCM token ${newFcm}`);
                await User.updateMany({ fcmToken: apnsToken }, { fcmToken: newFcm }).catch(() => {});
                return newFcm;
            }
        }
    } catch (err) {
        console.error('APNs to FCM conversion failed:', err.message);
    }
    return null;
};

/**
 * Sends a push notification to a user's FCM token.
 * @param {string} fcmToken - The FCM registration token of the device.
 * @param {Object} payload - The notification payload.
 * @param {string} payload.title - Notification title.
 * @param {string} payload.body - Notification body.
 * @param {Object} [payload.data] - Optional key-value data payload.
 */
export const sendPushNotification = async (fcmToken, { title, body, data = {}, sound = 'default', priority = 'high' }) => {
    if (!fcmToken) return;

    if (!firebaseMessaging) {
        console.log(`[SIMULATED PUSH] To: ${fcmToken} | Title: "${title}" | Body: "${body}" | Data:`, data);
        return;
    }

    let targetToken = fcmToken;
    if (/^[0-9a-fA-F]{64}$/.test(fcmToken)) {
        console.log(`Detected 64-char APNs device token [${fcmToken}]. Converting to FCM token...`);
        const converted = await convertApnsToFcmToken(fcmToken);
        if (converted) {
            targetToken = converted;
        }
    }

    try {
        const message = {
            token: targetToken,
            notification: {
                title,
                body,
            },
            data: {
                click_action: 'FLUTTER_NOTIFICATION_CLICK',
                ...data,
            },
            android: {
                priority: priority === 'high' ? 'high' : 'normal',
                notification: {
                    sound: sound || 'default',
                    channelId: 'high_importance_channel',
                    priority: 'high',
                    defaultSound: true,
                    defaultVibrateTimings: true,
                },
            },
            apns: {
                headers: {
                    'apns-priority': '10',
                },
                payload: {
                    aps: {
                        alert: {
                            title,
                            body,
                        },
                        sound: sound || 'default',
                        badge: 1,
                        contentAvailable: true,
                    },
                },
            },
        };

        const response = await firebaseMessaging.send(message);
        console.log(`Push notification sent successfully to ${fcmToken}:`, response);
    } catch (error) {
        console.error(`Error sending push notification to ${fcmToken}:`, error.message);
        if (error.message && (error.message.includes('NotRegistered') || error.code === 'messaging/registration-token-not-registered')) {
            console.log(`Clearing stale FCM token ${fcmToken} from database...`);
            await User.updateMany({ fcmToken }, { $unset: { fcmToken: 1 } }).catch(() => {});
        }
    }
};
