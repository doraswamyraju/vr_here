import admin from 'firebase-admin';
import dotenv from 'dotenv';

dotenv.config();

let firebaseMessaging = null;
let firebaseDb = null;
let firebaseAuth = null;

try {
    const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
    const serviceAccountPath = process.env.FIREBASE_CREDENTIALS_PATH;

    if (serviceAccountJson) {
        const credentials = JSON.parse(serviceAccountJson);
        admin.initializeApp({
            credential: admin.credential.cert(credentials),
        });
        firebaseMessaging = admin.messaging();
        firebaseDb = admin.firestore();
        firebaseAuth = admin.auth();
        console.log('Firebase Admin initialized successfully using env variable FIREBASE_SERVICE_ACCOUNT.');
    } else if (serviceAccountPath) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountPath),
        });
        firebaseMessaging = admin.messaging();
        firebaseDb = admin.firestore();
        firebaseAuth = admin.auth();
        console.log(`Firebase Admin initialized successfully using service account key file at ${serviceAccountPath}.`);
    } else {
        console.warn('Firebase Admin: No credentials provided in environment variables (FIREBASE_SERVICE_ACCOUNT or FIREBASE_CREDENTIALS_PATH). Firebase features will be simulated.');
    }
} catch (error) {
    console.error('Failed to initialize Firebase Admin SDK. Firebase features will be simulated:', error.message);
}

/**
 * Sends a push notification to a user's FCM token.
 * @param {string} fcmToken - The FCM registration token of the device.
 * @param {Object} payload - The notification payload.
 * @param {string} payload.title - Notification title.
 * @param {string} payload.body - Notification body.
 * @param {Object} [payload.data] - Optional key-value data payload.
 */
export const sendPushNotification = async (fcmToken, { title, body, data = {} }) => {
    if (!fcmToken) return;

    if (!firebaseMessaging) {
        console.log(`[SIMULATED PUSH] To: ${fcmToken} | Title: "${title}" | Body: "${body}" | Data:`, data);
        return;
    }

    try {
        const message = {
            token: fcmToken,
            notification: {
                title,
                body,
            },
            data: {
                click_action: 'FLUTTER_NOTIFICATION_CLICK', // standard fallback for background routing
                ...data,
            },
            android: {
                notification: {
                    sound: 'default',
                    clickAction: 'MainActivity',
                },
            },
        };

        const response = await firebaseMessaging.send(message);
        console.log(`Push notification sent successfully to ${fcmToken}:`, response);
    } catch (error) {
        console.error(`Error sending push notification to ${fcmToken}:`, error.message);
    }
};

/**
 * Generates a Firebase Custom Token for a user.
 * @param {string} userId - The MongoDB User ID
 * @returns {Promise<string|null>} - The custom token or null
 */
export const generateFirebaseToken = async (userId) => {
    if (!firebaseAuth) {
        console.log(`[SIMULATED AUTH] Generating token for User: ${userId}`);
        return `mock-firebase-token-for-${userId}`;
    }
    try {
        const customToken = await firebaseAuth.createCustomToken(userId.toString());
        return customToken;
    } catch (error) {
        console.error('Error generating Firebase Custom Token:', error.message);
        return null;
    }
};

export { firebaseDb };

