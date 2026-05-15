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
// @access  Private/Admin
const createComplianceRecord = asyncHandler(async (req, res) => {
    const { clientName, category, taskName, dueDate, periodMonth, periodYear, notes } = req.body;
    
    const record = await Compliance.create({
        clientName,
        category,
        taskName,
        dueDate,
        periodMonth,
        periodYear,
        notes,
        status: 'Pending'
    });

    res.status(201).json(record);
});

// @desc    Update compliance status
// @route   PUT /api/compliance/:id
// @access  Private/Admin
const updateComplianceStatus = asyncHandler(async (req, res) => {
    const record = await Compliance.findById(req.params.id);

    if (record) {
        record.status = req.body.status || record.status;
        record.filedAt = req.body.status === 'Filed' ? new Date() : record.filedAt;
        record.notes = req.body.notes || record.notes;
        
        const updatedRecord = await record.save();
        res.json(updatedRecord);
    } else {
        res.status(404);
        throw new Error('Record not found');
    }
});

// @desc    Bulk generate compliance for a month
// @route   POST /api/compliance/bulk-generate
// @access  Private/Admin
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
    bulkGenerateCompliance
};
