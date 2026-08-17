import asyncHandler from 'express-async-handler';
import Attendance from '../models/Attendance.js';
import Order from '../models/Order.js';
import User from '../models/User.js';

const getDateKey = (date = new Date()) => date.toISOString().slice(0, 10);

const parseDateRange = (query) => {
    const to = query.to ? new Date(query.to) : new Date();
    const from = query.from ? new Date(query.from) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    return { from, to };
};

// @desc    Employee clock in
// @route   POST /api/attendance/clock-in
// @access  Private (employee/admin)
const clockIn = asyncHandler(async (req, res) => {
    if (req.user.role !== 'employee' && req.user.role !== 'admin') {
        res.status(403);
        throw new Error('Only staff can clock in');
    }

    const open = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    if (open) {
        return res.status(200).json({ message: 'Already clocked in', session: open });
    }

    const now = new Date();
    const attendance = await Attendance.create({
        employee: req.user._id,
        clockInAt: now,
        dateKey: getDateKey(now),
        source: req.body.source || 'employee-dashboard'
    });

    res.status(201).json({ message: 'Clocked in', session: attendance });
});

// @desc    Employee clock out
// @route   POST /api/attendance/clock-out
// @access  Private (employee/admin)
const clockOut = asyncHandler(async (req, res) => {
    if (req.user.role !== 'employee' && req.user.role !== 'admin') {
        res.status(403);
        throw new Error('Only staff can clock out');
    }

    const open = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    if (!open) {
        res.status(400);
        throw new Error('No active clock-in session found');
    }

    const now = new Date();
    open.clockOutAt = now;
    open.totalSeconds = Math.max(0, Math.floor((now.getTime() - new Date(open.clockInAt).getTime()) / 1000));
    await open.save();

    res.json({ message: 'Clocked out', session: open });
});

// @desc    Get my attendance status and totals
// @route   GET /api/attendance/my-status
// @access  Private
const getMyAttendanceStatus = asyncHandler(async (req, res) => {
    const openSession = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    const todayKey = getDateKey(new Date());
    const todayRecords = await Attendance.find({ employee: req.user._id, dateKey: todayKey });
    const todayWorkedSeconds = todayRecords.reduce((sum, item) => sum + Number(item.totalSeconds || 0), 0);

    const user = await User.findById(req.user._id).select('isClockedIn lastClockInTime activeOrderId');

    res.json({
        openSession,
        userClockIn: user ? {
            isClockedIn: Boolean(user.isClockedIn),
            lastClockInTime: user.lastClockInTime,
            activeOrderId: user.activeOrderId
        } : null,
        todayWorkedSeconds,
        todayRecordsCount: todayRecords.length
    });
});

// @desc    Get attendance logs for current user
// @route   GET /api/attendance/my-logs
// @access  Private
const getMyAttendanceLogs = asyncHandler(async (req, res) => {
    const { from, to } = parseDateRange(req.query);
    const logs = await Attendance.find({
        employee: req.user._id,
        clockInAt: { $gte: from, $lte: to }
    }).sort({ clockInAt: -1 });

    res.json(logs);
});

// @desc    Admin summary: worked time vs tracked task time
// @route   GET /api/attendance/admin/summary
// @access  Private/Admin
const getAdminAttendanceSummary = asyncHandler(async (req, res) => {
    const { from, to } = parseDateRange(req.query);

    const attendanceRows = await Attendance.find({
        clockInAt: { $gte: from, $lte: to }
    }).populate('employee', 'name email role isActive');

    const summaryByEmployee = new Map();

    attendanceRows.forEach((row) => {
        const employee = row.employee;
        if (!employee?._id) return;
        const key = employee._id.toString();
        if (!summaryByEmployee.has(key)) {
            summaryByEmployee.set(key, {
                employeeId: key,
                employeeName: employee.name,
                employeeEmail: employee.email,
                isActive: employee.isActive,
                workedSeconds: 0,
                trackedMinutes: 0,
                trackedByOrder: {},
                sessions: 0
            });
        }

        const current = summaryByEmployee.get(key);
        const liveSeconds = row.clockOutAt
            ? Number(row.totalSeconds || 0)
            : Math.max(0, Math.floor((Date.now() - new Date(row.clockInAt).getTime()) / 1000));
        current.workedSeconds += liveSeconds;
        current.sessions += 1;
    });

    const orders = await Order.find({}).select('serviceName tasks');
    orders.forEach((order) => {
        (order.tasks || []).forEach((task) => {
            (task.timeLogs || []).forEach((log) => {
                const loggedAt = log.loggedAt ? new Date(log.loggedAt) : null;
                if (!loggedAt || loggedAt < from || loggedAt > to) return;
                const employeeId = log.employee?.toString?.() || '';
                if (!employeeId) return;

                if (!summaryByEmployee.has(employeeId)) {
                    summaryByEmployee.set(employeeId, {
                        employeeId,
                        employeeName: 'Unknown',
                        employeeEmail: '',
                        isActive: true,
                        workedSeconds: 0,
                        trackedMinutes: 0,
                        trackedByOrder: {},
                        sessions: 0
                    });
                }

                const current = summaryByEmployee.get(employeeId);
                const minutes = Number(log.minutes || 0);
                current.trackedMinutes += minutes;
                current.trackedByOrder[order.serviceName] = (current.trackedByOrder[order.serviceName] || 0) + minutes;
            });
        });
    });

    const items = Array.from(summaryByEmployee.values())
        .map((item) => {
            const workedMinutes = Math.round(item.workedSeconds / 60);
            const untrackedMinutes = Math.max(0, workedMinutes - item.trackedMinutes);
            const productivity = workedMinutes > 0 ? Math.round((item.trackedMinutes / workedMinutes) * 100) : 0;
            return {
                ...item,
                workedMinutes,
                untrackedMinutes,
                productivityPercent: productivity
            };
        })
        .sort((a, b) => b.workedSeconds - a.workedSeconds);

    res.json({
        from,
        to,
        items
    });
});

// @desc    Get detailed analysis for a specific employee
// @route   GET /api/attendance/admin/employee/:id
// @access  Private/Admin
const getEmployeeAnalysis = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { from, to } = parseDateRange(req.query);

    // 1. Get Attendance Sessions
    const sessions = await Attendance.find({
        employee: id,
        clockInAt: { $gte: from, $lte: to }
    }).sort({ clockInAt: 1 });

    // 2. Get Task Time Logs
    const orders = await Order.find({
        'tasks.timeLogs.employee': id,
        'tasks.timeLogs.loggedAt': { $gte: from, $lte: to }
    }).select('serviceName tasks');

    const taskLogs = [];
    orders.forEach(order => {
        order.tasks.forEach(task => {
            task.timeLogs.forEach(log => {
                if (log.employee?.toString() === id && log.loggedAt >= from && log.loggedAt <= to) {
                    taskLogs.push({
                        orderId: order._id,
                        serviceName: order.serviceName,
                        taskId: task._id,
                        taskTitle: task.title,
                        minutes: log.minutes,
                        notes: log.notes,
                        loggedAt: log.loggedAt
                    });
                }
            });
        });
    });

    // 3. Daily Breakdown
    const days = {};
    const curr = new Date(from);
    while (curr <= to) {
        const key = getDateKey(curr);
        days[key] = {
            date: key,
            workedMinutes: 0,
            trackedMinutes: 0,
            sessions: [],
            logs: []
        };
        curr.setDate(curr.getDate() + 1);
    }

    sessions.forEach(s => {
        const key = getDateKey(s.clockInAt);
        if (days[key]) {
            days[key].workedMinutes += Math.round((s.totalSeconds || 0) / 60);
            days[key].sessions.push(s);
        }
    });

    taskLogs.forEach(l => {
        const key = getDateKey(l.loggedAt);
        if (days[key]) {
            days[key].trackedMinutes += l.minutes;
            days[key].logs.push(l);
        }
    });

    res.json({
        employeeId: id,
        from,
        to,
        dailyBreakdown: Object.values(days).sort((a, b) => b.date.localeCompare(a.date)),
        totalWorkedMinutes: sessions.reduce((s, row) => s + Math.round((row.totalSeconds || 0) / 60), 0),
        totalTrackedMinutes: taskLogs.reduce((s, row) => s + row.minutes, 0),
        sessionsCount: sessions.length,
        logsCount: taskLogs.length
    });
});

export {
    clockIn,
    clockOut,
    getMyAttendanceStatus,
    getMyAttendanceLogs,
    getAdminAttendanceSummary,
    getEmployeeAnalysis
};
