import asyncHandler from 'express-async-handler';
import Compliance from '../models/Compliance.js';

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

// @desc    Create a compliance record
// @route   POST /api/compliance
// @access  Private (Admin or Authorized Employee)
const createComplianceRecord = asyncHandler(async (req, res) => {
    const { clientName, category, taskName, dueDate, periodMonth, periodYear, notes, status, assignedTo } = req.body;
    
    const record = await Compliance.create({
        clientName,
        category,
        taskName,
        dueDate,
        periodMonth,
        periodYear,
        notes: notes || '',
        status: status || 'Pending',
        assignedTo: assignedTo || null
    });

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
