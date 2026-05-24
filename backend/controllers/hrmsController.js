import asyncHandler from 'express-async-handler';
import Leave from '../models/Leave.js';
import Holiday from '../models/Holiday.js';
import Notice from '../models/Notice.js';
import User from '../models/User.js';
import Attendance from '../models/Attendance.js';
import { triggerNotification, notifyAdmins } from '../services/notificationService.js';

const getDateKey = (date = new Date()) => date.toISOString().slice(0, 10);

// ==========================================
// LEAVE CONTROLLERS
// ==========================================

// @desc    Apply for a leave
// @route   POST /api/hrms/leaves
// @access  Private (employee/admin/partner/client)
export const applyLeave = asyncHandler(async (req, res) => {
    const { startDate, endDate, type, reason } = req.body;

    if (!startDate || !endDate || !reason) {
        res.status(400);
        throw new Error('Start date, end date, and reason are required');
    }

    const leave = await Leave.create({
        employee: req.user._id,
        startDate: new Date(startDate),
        endDate: new Date(endDate),
        type: type || 'Casual',
        reason
    });

    // Notify all admins about the new leave request
    const startStr = new Date(startDate).toLocaleDateString();
    const endStr = new Date(endDate).toLocaleDateString();
    await notifyAdmins({
        title: 'New Leave Application',
        message: `${req.user.name} has requested ${type || 'Casual'} leave from ${startStr} to ${endStr}. Reason: ${reason}`,
        type: 'System',
        email: true
    });

    res.status(201).json({ success: true, leave });
});

// @desc    Get my leaves
// @route   GET /api/hrms/leaves/my
// @access  Private
export const getMyLeaves = asyncHandler(async (req, res) => {
    const leaves = await Leave.find({ employee: req.user._id }).sort({ createdAt: -1 });
    res.json(leaves);
});

// @desc    Get all leaves (Admin only)
// @route   GET /api/hrms/leaves/admin
// @access  Private/Admin
export const getAdminLeaves = asyncHandler(async (req, res) => {
    const leaves = await Leave.find({})
        .populate('employee', 'name email phone role isActive')
        .sort({ createdAt: -1 });
    res.json(leaves);
});

// @desc    Approve/Reject a leave (Admin only)
// @route   PUT /api/hrms/leaves/:id/approve
// @access  Private/Admin
export const approveLeave = asyncHandler(async (req, res) => {
    const { status, adminNotes } = req.body;
    const leaveId = req.params.id;

    if (!['Approved', 'Rejected'].includes(status)) {
        res.status(400);
        throw new Error('Status must be Approved or Rejected');
    }

    const leave = await Leave.findById(leaveId).populate('employee', 'name email');

    if (!leave) {
        res.status(404);
        throw new Error('Leave application not found');
    }

    leave.status = status;
    leave.approvedBy = req.user._id;
    leave.adminNotes = adminNotes || '';
    await leave.save();

    // Trigger instant notification to employee
    const startStr = new Date(leave.startDate).toLocaleDateString();
    const endStr = new Date(leave.endDate).toLocaleDateString();
    await triggerNotification({
        userId: leave.employee._id,
        title: `Leave Request ${status}`,
        message: `Your leave request from ${startStr} to ${endStr} has been ${status.toLowerCase()} by admin.${adminNotes ? ' Notes: ' + adminNotes : ''}`,
        type: 'System',
        emailOpts: {
            send: true,
            subject: `VR HERE: Leave Application ${status}`
        }
    });

    res.json({ success: true, leave });
});


// ==========================================
// HOLIDAY CONTROLLERS
// ==========================================

// @desc    Create holiday (Admin only)
// @route   POST /api/hrms/holidays
// @access  Private/Admin
export const createHoliday = asyncHandler(async (req, res) => {
    const { title, date, description } = req.body;

    if (!title || !date) {
        res.status(400);
        throw new Error('Title and date are required');
    }

    const holiday = await Holiday.create({
        title,
        date: new Date(date),
        description: description || ''
    });

    // Notify all active employees and clients about the new holiday
    const dateStr = new Date(date).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    const employees = await User.find({ isActive: true });
    
    for (const emp of employees) {
        // Fire alerts asynchronously
        triggerNotification({
            userId: emp._id,
            title: `Holiday Declared: ${title}`,
            message: `Notice: A company holiday has been declared for ${dateStr}.${description ? ' Details: ' + description : ''}`,
            type: 'System',
            emailOpts: {
                send: emp.role === 'employee', // Only email staff
                subject: `VR HERE Bulletin: Holiday - ${title}`
            }
        }).catch(err => console.error('Holiday alert fail:', err.message));
    }

    res.status(201).json({ success: true, holiday });
});

// @desc    Get all holidays
// @route   GET /api/hrms/holidays
// @access  Private
export const getHolidays = asyncHandler(async (req, res) => {
    const holidays = await Holiday.find({}).sort({ date: 1 });
    res.json(holidays);
});

// @desc    Delete holiday (Admin only)
// @route   DELETE /api/hrms/holidays/:id
// @access  Private/Admin
export const deleteHoliday = asyncHandler(async (req, res) => {
    const holiday = await Holiday.findById(req.params.id);
    if (!holiday) {
        res.status(404);
        throw new Error('Holiday not found');
    }
    await Holiday.deleteOne({ _id: req.params.id });
    res.json({ success: true, message: 'Holiday deleted' });
});


// ==========================================
// NOTICE CONTROLLERS
// ==========================================

// @desc    Create a notice board publication (Admin only)
// @route   POST /api/hrms/notices
// @access  Private/Admin
export const createNotice = asyncHandler(async (req, res) => {
    const { title, message, priority } = req.body;

    if (!title || !message) {
        res.status(400);
        throw new Error('Title and message are required');
    }

    const notice = await Notice.create({
        title,
        message,
        priority: priority || 'Medium',
        issuedBy: req.user._id
    });

    // Notify all active employees
    const employees = await User.find({ role: 'employee', isActive: true });
    for (const emp of employees) {
        triggerNotification({
            userId: emp._id,
            title: `New Notice: ${title}`,
            message: message,
            type: 'System',
            emailOpts: {
                send: priority === 'High', // Email staff if high priority
                subject: `URGENT Notice: ${title}`
            }
        }).catch(err => console.error('Notice alert fail:', err.message));
    }

    res.status(201).json({ success: true, notice });
});

// @desc    Get notices
// @route   GET /api/hrms/notices
// @access  Private
export const getNotices = asyncHandler(async (req, res) => {
    const notices = await Notice.find({})
        .populate('issuedBy', 'name')
        .sort({ createdAt: -1 });
    res.json(notices);
});

// @desc    Delete a notice (Admin only)
// @route   DELETE /api/hrms/notices/:id
// @access  Private/Admin
export const deleteNotice = asyncHandler(async (req, res) => {
    const notice = await Notice.findById(req.params.id);
    if (!notice) {
        res.status(404);
        throw new Error('Notice not found');
    }
    await Notice.deleteOne({ _id: req.params.id });
    res.json({ success: true, message: 'Notice deleted' });
});


// ==========================================
// LIVE WORKLOAD & ATTENDANCE DASHBOARD
// ==========================================

// @desc    Get live operational grid of clocked in, clocked out and on leave employees (Admin only)
// @route   GET /api/hrms/admin/live-status
// @access  Private/Admin
export const getLiveStatus = asyncHandler(async (req, res) => {
    const today = new Date();
    const todayStr = getDateKey(today);

    // 1. Fetch active employees
    const employees = await User.find({ role: 'employee', isActive: true }).select('name email phone');

    // 2. Fetch today's clocked-in sessions
    const activeSessions = await Attendance.find({
        dateKey: todayStr,
        clockOutAt: null
    }).select('employee clockInAt source');

    const activeEmpIds = new Set(activeSessions.map(s => s.employee.toString()));

    // 3. Fetch today's approved leaves
    const leavesToday = await Leave.find({
        status: 'Approved',
        startDate: { $lte: today },
        endDate: { $gte: today }
    }).select('employee type reason');

    const leaveEmpIds = new Set(leavesToday.map(l => l.employee.toString()));

    // 4. Group employees
    const clockedIn = [];
    const onLeave = [];
    const offline = [];

    employees.forEach(emp => {
        const empId = emp._id.toString();
        const session = activeSessions.find(s => s.employee.toString() === empId);
        const leave = leavesToday.find(l => l.employee.toString() === empId);

        if (session) {
            clockedIn.push({
                _id: emp._id,
                name: emp.name,
                email: emp.email,
                phone: emp.phone,
                clockInAt: session.clockInAt,
                source: session.source
            });
        } else if (leave) {
            onLeave.push({
                _id: emp._id,
                name: emp.name,
                email: emp.email,
                phone: emp.phone,
                leaveType: leave.type,
                reason: leave.reason
            });
        } else {
            offline.push({
                _id: emp._id,
                name: emp.name,
                email: emp.email,
                phone: emp.phone
            });
        }
    });

    res.json({
        date: todayStr,
        clockedIn,
        onLeave,
        offline
    });
});
