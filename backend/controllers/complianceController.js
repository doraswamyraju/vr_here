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

// @desc    Create a compliance record & optional broadcast notification
// @route   POST /api/compliance
// @access  Private (Admin or Authorized Employee)
const createComplianceRecord = asyncHandler(async (req, res) => {
    const { clientName, category, taskName, dueDate, periodMonth, periodYear, notes, status, assignedTo, sendBroadcast } = req.body;
    
    const isAllClients = !clientName || clientName.trim() === '' || clientName.toLowerCase() === 'all clients' || clientName.toLowerCase() === 'all active clients';
    const recordClientName = isAllClients ? 'All Active Clients' : clientName.trim();

    const record = await Compliance.create({
        clientName: recordClientName,
        category,
        taskName,
        dueDate,
        periodMonth,
        periodYear,
        notes: notes || '',
        status: status || 'Pending',
        assignedTo: assignedTo || null
    });

    // If broadcast is requested or client is "All Active Clients", trigger In-App, Push & Email to all clients!
    if (sendBroadcast || isAllClients) {
        const clients = await User.find({ role: 'client', isActive: true });
        const formattedDueDate = new Date(dueDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
        const notifTitle = `Statutory Compliance Alert: ${category} - ${taskName}`;
        const notifMessage = `Important Compliance Alert for ${periodMonth} ${periodYear}: ${taskName} is due on ${formattedDueDate}. Please ensure all required documents and details are submitted on time.`;

        // Async broadcast without delaying HTTP response
        clients.forEach(client => {
            triggerNotification({
                userId: client._id,
                title: notifTitle,
                message: notifMessage,
                type: 'System',
                emailOpts: {
                    send: true,
                    subject: `[VR HERE] Statutory Deadline Alert: ${category} - ${taskName} (${formattedDueDate})`
                }
            }).catch(err => console.error(`Failed compliance alert to ${client.email}:`, err.message));
        });
    }

    res.status(201).json(record);
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
