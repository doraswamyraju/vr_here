export const calculateNextRunDate = (frequency, dayOfMonth, dayOfWeek, startDate = new Date()) => {
    let nextDate = new Date(startDate);
    
    // Ensure we are working with at least tomorrow to avoid infinite loops if run multiple times today
    nextDate.setDate(nextDate.getDate() + 1);

    if (frequency === 'Weekly') {
        const currentDay = nextDate.getDay(); // 0-6 (Sun-Sat)
        // Adjust for target day (1-7, Mon-Sun)
        let target = dayOfWeek % 7; // 1-6 remains, 7 becomes 0 (Sun)
        let diff = target - currentDay;
        if (diff < 0) diff += 7;
        nextDate.setDate(nextDate.getDate() + diff);
    } else if (frequency === 'Monthly') {
        nextDate.setMonth(nextDate.getMonth() + 1);
        nextDate.setDate(dayOfMonth);
    } else if (frequency === 'Quarterly') {
        nextDate.setMonth(nextDate.getMonth() + 3);
        nextDate.setDate(dayOfMonth);
    } else if (frequency === 'Half-Yearly') {
        nextDate.setMonth(nextDate.getMonth() + 6);
        nextDate.setDate(dayOfMonth);
    } else if (frequency === 'Yearly') {
        nextDate.setFullYear(nextDate.getFullYear() + 1);
        nextDate.setDate(dayOfMonth);
    }
    
    return nextDate;
};
