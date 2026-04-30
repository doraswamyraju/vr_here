import asyncHandler from 'express-async-handler';
import Finance from '../models/Finance.js';

// @desc    Create a new finance record
// @route   POST /api/finance
// @access  Private/Admin/Employee
const createFinanceRecord = asyncHandler(async (req, res) => {
    const record = new Finance({
        ...req.body,
        createdBy: req.user._id
    });

    const createdRecord = await record.save();
    res.status(201).json(createdRecord);
});

// @desc    Get all finance records with filtering
// @route   GET /api/finance
// @access  Private
const getFinanceRecords = asyncHandler(async (req, res) => {
    const { type, clientId, status } = req.query;
    
    let query = {};
    if (type) query.type = type;
    if (status) query.status = status;

    // Role based access
    if (req.user.role === 'client') {
        query['client.user'] = req.user._id;
    } else if (req.user.role === 'partner') {
        // Partners might see their own commission invoices?
        query['client.user'] = req.user._id;
    } else if (req.user.role === 'employee') {
        // Employees see all for now, or we could filter by linkedOrder assigned to them
    }

    if (clientId) query['client.user'] = clientId;

    const records = await Finance.find(query)
        .populate('linkedOrder', 'serviceName packageName')
        .sort({ createdAt: -1 });
        
    res.json(records);
});

// @desc    Get single finance record
// @route   GET /api/finance/:id
// @access  Private
const getFinanceRecordById = asyncHandler(async (req, res) => {
    const record = await Finance.findById(req.params.id)
        .populate('linkedOrder', 'serviceName packageName')
        .populate('createdBy', 'name');

    if (record) {
        // Authorization check
        if (req.user.role === 'client' && record.client.user.toString() !== req.user._id.toString()) {
            res.status(403);
            throw new Error('Not authorized to view this record');
        }
        res.json(record);
    } else {
        res.status(404);
        throw new Error('Record not found');
    }
});

// @desc    Update finance record
// @route   PUT /api/finance/:id
// @access  Private/Admin/Employee
const updateFinanceRecord = asyncHandler(async (req, res) => {
    const record = await Finance.findById(req.params.id);

    if (record) {
        Object.assign(record, req.body);
        const updatedRecord = await record.save();
        res.json(updatedRecord);
    } else {
        res.status(404);
        throw new Error('Record not found');
    }
});

// @desc    Delete finance record
// @route   DELETE /api/finance/:id
// @access  Private/Admin
const deleteFinanceRecord = asyncHandler(async (req, res) => {
    const record = await Finance.findById(req.params.id);

    if (record) {
        await record.deleteOne();
        res.json({ message: 'Record removed' });
    } else {
        res.status(404);
        throw new Error('Record not found');
    }
});

export {
    createFinanceRecord,
    getFinanceRecords,
    getFinanceRecordById,
    updateFinanceRecord,
    deleteFinanceRecord
};
