import OrderHistory from '../models/OrderHistory.js';

/**
 * Logs an activity performed on an order
 * @param {string} orderId - The target order ID
 * @param {string} userId - The user ID who performed the action
 * @param {string} action - The action type (e.g. 'STATUS_CHANGE', 'DOCUMENT_UPLOAD')
 * @param {string} description - Human-readable explanation of the action
 * @param {object} [metadata] - Optional additional debug/context info
 */
export const logOrderActivity = async (orderId, userId, action, description, metadata = {}) => {
    try {
        if (!orderId || !userId) {
            console.error('Cannot log order activity: Missing orderId or userId');
            return null;
        }
        const historyEntry = new OrderHistory({
            order: orderId,
            user: userId,
            action,
            description,
            metadata
        });
        await historyEntry.save();
        return historyEntry;
    } catch (err) {
        console.error('Error logging order activity:', err.message);
        return null;
    }
};
