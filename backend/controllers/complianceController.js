import asyncHandler from 'express-async-handler';
import Compliance from '../models/Compliance.js';
import User from '../models/User.js';
import { triggerNotification } from '../services/notificationService.js';

// @desc    Get all compliance records
// @route   GET /api/compliance
// @access  Private/Admin
const getComplianceRecords = asyncHandler(async (req, res) => {
    const { category, clientName, month, year } = req.query;
    const query = {};
    if (category) query.category = category;
    if (clientName) query.clientName = { $regex: clientName, $options: 'i' };
    if (month) query.periodMonth = month;
    if (year) query.periodYear = year;

    const records = await Compliance.find(query).sort({ dueDate: 1 });
    res.json(records);
});

// Financial Year Month definitions: April (04) of Start Year to March (03) of Next Year
const FY_MONTHS = [
    { code: 'APR', monthIdx: 3, yearOffset: 0 },
    { code: 'MAY', monthIdx: 4, yearOffset: 0 },
    { code: 'JUN', monthIdx: 5, yearOffset: 0 },
    { code: 'JUL', monthIdx: 6, yearOffset: 0 },
    { code: 'AUG', monthIdx: 7, yearOffset: 0 },
    { code: 'SEP', monthIdx: 8, yearOffset: 0 },
    { code: 'OCT', monthIdx: 9, yearOffset: 0 },
    { code: 'NOV', monthIdx: 10, yearOffset: 0 },
    { code: 'DEC', monthIdx: 11, yearOffset: 0 },
    { code: 'JAN', monthIdx: 0, yearOffset: 1 },
    { code: 'FEB', monthIdx: 1, yearOffset: 1 },
    { code: 'MAR', monthIdx: 2, yearOffset: 1 }
];

// @desc    Create a compliance record (or auto-generate recurring FY schedule) & optional broadcast notification
// @route   POST /api/compliance
// @access  Private (Admin or Authorized Employee)
const createComplianceRecord = asyncHandler(async (req, res) => {
    const { clientName, category, taskName, dueDate, periodMonth, periodYear, notes, status, sendBroadcast, isRecurring, repeatFrequency, generateFullYear } = req.body;
    
    const isAllClients = !clientName || clientName.trim() === '' || clientName.toLowerCase() === 'all clients' || clientName.toLowerCase() === 'all active clients';
    const recordClientName = isAllClients ? 'All Active Clients' : clientName.trim();

    const baseDueDate = new Date(dueDate);
    const dayOfMonth = baseDueDate.getDate();
    const startFYYear = Number(periodYear) || baseDueDate.getFullYear();

    const recordsToInsert = [];

    if (generateFullYear || (isRecurring && repeatFrequency === 'Monthly')) {
        // Auto-generate recurring monthly entries for all 12 months of the Financial Year!
        FY_MONTHS.forEach(m => {
            const itemYear = startFYYear + m.yearOffset;
            const itemDueDate = new Date(itemYear, m.monthIdx, Math.min(dayOfMonth, 28));

            recordsToInsert.push({
                clientName: recordClientName,
                category,
                taskName,
                dueDate: itemDueDate,
                periodMonth: m.code,
                periodYear: String(itemYear),
                notes: notes || '',
                status: status || 'Pending'
            });
        });
    } else if (isRecurring && repeatFrequency === 'Quarterly') {
        // Auto-generate quarterly entries (JUN, SEP, DEC, MAR)
        const quarterlyMonths = [
            { code: 'JUN', monthIdx: 5, yearOffset: 0 },
            { code: 'SEP', monthIdx: 8, yearOffset: 0 },
            { code: 'DEC', monthIdx: 11, yearOffset: 0 },
            { code: 'MAR', monthIdx: 2, yearOffset: 1 }
        ];

        quarterlyMonths.forEach(m => {
            const itemYear = startFYYear + m.yearOffset;
            const itemDueDate = new Date(itemYear, m.monthIdx, Math.min(dayOfMonth, 28));

            recordsToInsert.push({
                clientName: recordClientName,
                category,
                taskName,
                dueDate: itemDueDate,
                periodMonth: m.code,
                periodYear: String(itemYear),
                notes: notes || '',
                status: status || 'Pending'
            });
        });
    } else {
        // Single One-Time Entry
        recordsToInsert.push({
            clientName: recordClientName,
            category,
            taskName,
            dueDate: baseDueDate,
            periodMonth: periodMonth || 'AUG',
            periodYear: String(startFYYear),
            notes: notes || '',
            status: status || 'Pending'
        });
    }

    const createdRecords = await Compliance.insertMany(recordsToInsert);

    // If broadcast is requested, trigger In-App, Push & Email to all clients!
    if (sendBroadcast || isAllClients) {
        const clients = await User.find({ role: 'client', isActive: true });
        const formattedDueDate = baseDueDate.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
        const notifTitle = `Statutory Compliance Alert: ${category} - ${taskName}`;
        const notifMessage = `Important Compliance Alert: ${taskName} (${category}) is due on ${formattedDueDate} (Recurring ${repeatFrequency || 'Monthly'}). Please ensure all required documents and details are submitted on time.`;

        // Async broadcast without delaying HTTP response
        clients.forEach(client => {
            triggerNotification({
                userId: client._id,
                title: notifTitle,
                message: notifMessage,
                type: 'System',
                emailOpts: {
                    send: true,
                    subject: `[VR HERE] Statutory Deadline Alert: ${category} - ${taskName}`
                }
            }).catch(err => console.error(`Failed compliance alert to ${client.email}:`, err.message));
        });
    }

    res.status(201).json(createdRecords);
});

// @desc    Update compliance status & details
// @route   PUT /api/compliance/:id
// @access  Private (Admin or Authorized Employee)
const updateComplianceStatus = asyncHandler(async (req, res) => {
    const record = await Compliance.findById(req.params.id);

    if (record) {
        if (req.body.clientName) record.clientName = req.body.clientName;
        if (req.body.category) record.category = req.body.category;
        if (req.body.taskName) record.taskName = req.body.taskName;
        if (req.body.dueDate) record.dueDate = req.body.dueDate;
        if (req.body.periodMonth) record.periodMonth = req.body.periodMonth;
        if (req.body.periodYear) record.periodYear = req.body.periodYear;
        if (req.body.status) {
            record.status = req.body.status;
            if (req.body.status === 'Filed' && !record.filedAt) {
                record.filedAt = new Date();
            }
        }
        if (req.body.notes !== undefined) record.notes = req.body.notes;
        if (req.body.assignedTo !== undefined) record.assignedTo = req.body.assignedTo;
        
        const updatedRecord = await record.save();
        res.json(updatedRecord);
    } else {
        res.status(404);
        throw new Error('Record not found');
    }
});

// @desc    Delete compliance record
// @route   DELETE /api/compliance/:id
// @access  Private (Admin or Authorized Employee)
const deleteComplianceRecord = asyncHandler(async (req, res) => {
    const record = await Compliance.findById(req.params.id);

    if (record) {
        await Compliance.deleteOne({ _id: req.params.id });
        res.json({ message: 'Compliance record removed' });
    } else {
        res.status(404);
        throw new Error('Record not found');
    }
});

// @desc    Bulk generate compliance for a month
// @route   POST /api/compliance/bulk-generate
// @access  Private (Admin or Authorized Employee)
const bulkGenerateCompliance = asyncHandler(async (req, res) => {
    const { clients, month, year, tasks } = req.body;
    
    const newRecords = [];
    clients.forEach(client => {
        tasks.forEach(task => {
            newRecords.push({
                clientName: client,
                category: task.category,
                taskName: task.taskName,
                dueDate: task.dueDate,
                periodMonth: month,
                periodYear: year,
                status: 'Pending'
            });
        });
    });

    const created = await Compliance.insertMany(newRecords);
    res.status(201).json(created);
});

export {
    getComplianceRecords,
    createComplianceRecord,
    updateComplianceStatus,
    deleteComplianceRecord,
    bulkGenerateCompliance
};
