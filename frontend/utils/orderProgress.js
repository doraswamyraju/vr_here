/**
 * Unified Order Progress and Phase Stepper Helper for VR Here Customer Portal
 * Single source of truth for milestone completion percentages across Home, Orders List, and Order Details views.
 */

export const ORDER_PHASES = [
    { label: 'Documents Pending', key: 'Pending Documents', step: 1, percent: 20 },
    { label: 'Documents Verified', key: 'Documents Verified', step: 2, percent: 40 },
    { label: 'Processing at Portal', key: 'Processing at Portal', step: 3, percent: 60 },
    { label: 'Clarification / Action', key: 'Waiting for Clarification', step: 4, percent: 80 },
    { label: 'Completed', key: 'Completed', step: 5, percent: 100 }
];

export const getOrderStatusProgress = (status) => {
    switch (status) {
        case 'Pending Documents':
            return 20;
        case 'Documents Verified':
            return 40;
        case 'Processing at Portal':
            return 60;
        case 'Waiting for Clarification':
            return 80;
        case 'Completed':
            return 100;
        default:
            return 10;
    }
};

export const getPhaseStepIndex = (status) => {
    const found = ORDER_PHASES.findIndex((p) => p.key === status || p.label === status);
    return found !== -1 ? found + 1 : 1;
};
