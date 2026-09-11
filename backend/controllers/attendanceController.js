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
// @access  Private (employee/admin/freelancer)
const clockIn = asyncHandler(async (req, res) => {
    if (req.user.role !== 'employee' && req.user.role !== 'admin' && req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Only staff can clock in');
    }

    const open = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    if (open) {
        // If session is older than 14 hours, auto-cap it and create a fresh one
        const elapsedHours = (Date.now() - new Date(open.clockInAt).getTime()) / (1000 * 60 * 60);
        if (elapsedHours > 14) {
            const cappedTime = new Date(new Date(open.clockInAt).getTime() + 10 * 60 * 60 * 1000);
            open.clockOutAt = cappedTime;
            open.totalSeconds = 10 * 3600;
            open.netWorkedSeconds = Math.max(0, 10 * 3600 - (open.totalBreakSeconds || 0));
            open.clockOutReason = 'auto-capped';
            open.isAutoClosed = true;
            await open.save();
        } else {
            return res.status(200).json({ message: 'Already clocked in', session: open });
        }
    }

    const now = new Date();
    const attendance = await Attendance.create({
        employee: req.user._id,
        clockInAt: now,
        dateKey: getDateKey(now),
        source: req.body.source || 'employee-dashboard',
        notes: req.body.notes || '',
        breaks: [],
        totalBreakSeconds: 0,
        netWorkedSeconds: 0,
        clockOutReason: 'manual'
    });

    res.status(201).json({ message: 'Clocked in', session: attendance });
});

// @desc    Employee clock out
// @route   POST /api/attendance/clock-out
// @access  Private (employee/admin/freelancer)
const clockOut = asyncHandler(async (req, res) => {
    if (req.user.role !== 'employee' && req.user.role !== 'admin' && req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Only staff can clock out');
    }

    const open = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    if (!open) {
        return res.status(200).json({ message: 'No active session to clock out' });
    }

    const now = new Date();
    open.clockOutAt = now;
    
    // If a break is currently active, end it now
    if (open.breaks && open.breaks.length > 0) {
        const activeBreak = open.breaks.find(b => !b.endedAt);
        if (activeBreak) {
            activeBreak.endedAt = now;
            activeBreak.durationSeconds = Math.max(0, Math.floor((now.getTime() - new Date(activeBreak.startedAt).getTime()) / 1000));
        }
    }

    // Calculate total break seconds
    const totalBreakSecs = (open.breaks || []).reduce((acc, b) => acc + (b.durationSeconds || 0), 0);
    open.totalBreakSeconds = totalBreakSecs;

    const totalGross = Math.max(0, Math.floor((now.getTime() - new Date(open.clockInAt).getTime()) / 1000));
    open.totalSeconds = totalGross;
    open.netWorkedSeconds = Math.max(0, totalGross - totalBreakSecs);
    open.clockOutReason = req.body.clockOutReason || (req.body.source === 'auto-logout' ? 'auto-logout' : 'manual');
    if (req.body.accomplishments) {
        open.accomplishments = req.body.accomplishments;
    }
    if (req.body.notes) {
        open.notes = open.notes ? `${open.notes} | ${req.body.notes}` : req.body.notes;
    }

    await open.save();

    res.json({ message: 'Clocked out', session: open });
});

// @desc    Start a break (Lunch, Tea, Meeting, Personal)
// @route   POST /api/attendance/break-start
// @access  Private
const startBreak = asyncHandler(async (req, res) => {
    const open = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    if (!open) {
        res.status(400);
        throw new Error('You must be clocked in to start a break');
    }

    const activeBreak = (open.breaks || []).find(b => !b.endedAt);
    if (activeBreak) {
        return res.status(200).json({ message: 'Break already in progress', session: open, activeBreak });
    }

    const breakType = req.body.breakType || 'Lunch';
    const newBreak = {
        breakType,
        startedAt: new Date(),
        endedAt: null,
        durationSeconds: 0,
        notes: req.body.notes || ''
    };

    open.breaks.push(newBreak);
    await open.save();

    res.status(201).json({ message: `${breakType} break started`, session: open, activeBreak: newBreak });
});

// @desc    End active break / resume work
// @route   POST /api/attendance/break-end
// @access  Private
const endBreak = asyncHandler(async (req, res) => {
    const open = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    if (!open) {
        res.status(400);
        throw new Error('No active clock-in session found');
    }

    const activeBreak = (open.breaks || []).find(b => !b.endedAt);
    if (!activeBreak) {
        return res.status(200).json({ message: 'No active break in progress', session: open });
    }

    const now = new Date();
    activeBreak.endedAt = now;
    activeBreak.durationSeconds = Math.max(0, Math.floor((now.getTime() - new Date(activeBreak.startedAt).getTime()) / 1000));

    const totalBreakSecs = (open.breaks || []).reduce((acc, b) => acc + (b.durationSeconds || 0), 0);
    open.totalBreakSeconds = totalBreakSecs;
    await open.save();

    res.json({ message: 'Break ended, shift resumed', session: open });
});

// @desc    Admin adjust attendance record
// @route   PUT /api/attendance/admin/adjust/:id
// @access  Private/Admin
const adminAdjustAttendance = asyncHandler(async (req, res) => {
    const session = await Attendance.findById(req.params.id);
    if (!session) {
        res.status(404);
        throw new Error('Attendance session not found');
    }

    const { clockInAt, clockOutAt, notes, accomplishments, clockOutReason } = req.body;
    if (clockInAt) session.clockInAt = new Date(clockInAt);
    if (clockOutAt) session.clockOutAt = new Date(clockOutAt);
    if (notes !== undefined) session.notes = notes;
    if (accomplishments !== undefined) session.accomplishments = accomplishments;
    if (clockOutReason) session.clockOutReason = clockOutReason;

    if (session.clockOutAt && session.clockInAt) {
        const grossSecs = Math.max(0, Math.floor((new Date(session.clockOutAt).getTime() - new Date(session.clockInAt).getTime()) / 1000));
        session.totalSeconds = grossSecs;
        session.netWorkedSeconds = Math.max(0, grossSecs - (session.totalBreakSeconds || 0));
    }

    await session.save();
    res.json({ message: 'Attendance record adjusted successfully', session });
});

// @desc    Get my attendance status and totals
// @route   GET /api/attendance/my-status
// @access  Private
const getMyAttendanceStatus = asyncHandler(async (req, res) => {
    const openSession = await Attendance.findOne({ employee: req.user._id, clockOutAt: null }).sort({ clockInAt: -1 });
    const todayKey = getDateKey(new Date());
    const todayRecords = await Attendance.find({ employee: req.user._id, dateKey: todayKey });
    
    let todayWorkedSeconds = 0;
    let todayBreakSeconds = 0;
    let todayNetWorkedSeconds = 0;

    todayRecords.forEach(r => {
        const gross = r.clockOutAt 
            ? Number(r.totalSeconds || 0) 
            : Math.max(0, Math.floor((Date.now() - new Date(r.clockInAt).getTime()) / 1000));
        const brk = Number(r.totalBreakSeconds || 0);
        todayWorkedSeconds += gross;
        todayBreakSeconds += brk;
        todayNetWorkedSeconds += Math.max(0, gross - brk);
    });

    let activeBreak = null;
    if (openSession?.breaks && openSession.breaks.length > 0) {
        activeBreak = openSession.breaks.find(b => !b.endedAt) || null;
    }

    const user = await User.findById(req.user._id).select('isClockedIn lastClockInTime activeOrderId');

    res.json({
        openSession,
        activeBreak,
        userClockIn: user ? {
            isClockedIn: Boolean(user.isClockedIn),
            lastClockInTime: user.lastClockInTime,
            activeOrderId: user.activeOrderId
        } : null,
        todayWorkedSeconds,
        todayBreakSeconds,
        todayNetWorkedSeconds,
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
    startBreak,
    endBreak,
    adminAdjustAttendance,
    getMyAttendanceStatus,
    getMyAttendanceLogs,
    getAdminAttendanceSummary,
    getEmployeeAnalysis
};
