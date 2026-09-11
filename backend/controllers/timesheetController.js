import asyncHandler from 'express-async-handler';
import Timesheet from '../models/Timesheet.js';
import Attendance from '../models/Attendance.js';
import Order from '../models/Order.js';
import User from '../models/User.js';

const getDateKey = (date = new Date()) => date.toISOString().slice(0, 10);

const getDayOfWeek = (dateString) => {
    const d = new Date(dateString);
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return days[d.getDay()];
};

// @desc    Get my timesheet (compiled live with sync to database submission)
// @route   GET /api/timesheets/my-timesheet
// @access  Private
const getMyTimesheet = asyncHandler(async (req, res) => {
    const employeeId = req.user._id;
    let { startDate, endDate, periodType = 'weekly' } = req.query;

    if (!startDate || !endDate) {
        const now = new Date();
        const day = now.getDay();
        const diffToMonday = now.getDate() - day + (day === 0 ? -6 : 1);
        const monday = new Date(now.setDate(diffToMonday));
        const sunday = new Date(now.setDate(monday.getDate() + 6));
        startDate = getDateKey(monday);
        endDate = getDateKey(sunday);
    }

    const fromDate = new Date(`${startDate}T00:00:00.000Z`);
    const toDate = new Date(`${endDate}T23:59:59.999Z`);

    // 1. Check if an official submitted Timesheet doc exists
    let existingTimesheet = await Timesheet.findOne({
        employee: employeeId,
        startDate,
        endDate
    }).populate('reviewedBy', 'name email role');

    // 2. Fetch all raw Attendance records in range
    const attendanceRecords = await Attendance.find({
        employee: employeeId,
        clockInAt: { $gte: fromDate, $lte: toDate }
    }).sort({ clockInAt: 1 }).lean();

    // 3. Fetch all Task Time Logs in range
    const orders = await Order.find({
        'tasks.timeLogs.employee': employeeId,
        'tasks.timeLogs.loggedAt': { $gte: fromDate, $lte: toDate }
    }).select('serviceName tasks').lean();

    const taskLogsByDate = {};
    orders.forEach(order => {
        (order.tasks || []).forEach(task => {
            (task.timeLogs || []).forEach(log => {
                if (log.employee?.toString() === employeeId.toString()) {
                    const loggedDateKey = log.loggedAt ? getDateKey(new Date(log.loggedAt)) : null;
                    if (loggedDateKey) {
                        if (!taskLogsByDate[loggedDateKey]) taskLogsByDate[loggedDateKey] = [];
                        taskLogsByDate[loggedDateKey].push({
                            orderId: order._id,
                            serviceName: order.serviceName,
                            taskTitle: task.title,
                            minutes: Number(log.minutes || 0)
                        });
                    }
                }
            });
        });
    });

    // 4. Build Day-by-Day Entry Map
    const entries = [];
    const curr = new Date(fromDate);
    let totalGross = 0;
    let totalBreak = 0;
    let totalNet = 0;
    let totalTask = 0;
    let totalOvertime = 0;

    while (curr <= toDate) {
        const dKey = getDateKey(curr);
        const dayAttendance = attendanceRecords.filter(a => a.dateKey === dKey || getDateKey(new Date(a.clockInAt)) === dKey);
        const dayTaskLogs = taskLogsByDate[dKey] || [];

        let dayGrossSecs = 0;
        let dayBreakSecs = 0;
        let dayNetSecs = 0;
        let earliestIn = null;
        let latestOut = null;

        dayAttendance.forEach(a => {
            const gross = a.clockOutAt 
                ? Number(a.totalSeconds || 0) 
                : Math.max(0, Math.floor((Date.now() - new Date(a.clockInAt).getTime()) / 1000));
            const brk = Number(a.totalBreakSeconds || 0);
            dayGrossSecs += gross;
            dayBreakSecs += brk;
            dayNetSecs += Math.max(0, gross - brk);

            if (!earliestIn || new Date(a.clockInAt) < new Date(earliestIn)) {
                earliestIn = a.clockInAt;
            }
            if (a.clockOutAt && (!latestOut || new Date(a.clockOutAt) > new Date(latestOut))) {
                latestOut = a.clockOutAt;
            }
        });

        const dayTaskSecs = dayTaskLogs.reduce((acc, t) => acc + (t.minutes * 60), 0);
        const dayIdleSecs = Math.max(0, dayNetSecs - dayTaskSecs);
        const standardDaySecs = 8 * 3600; // 8 hrs standard shift
        const dayOvertimeSecs = Math.max(0, dayNetSecs - standardDaySecs);

        totalGross += dayGrossSecs;
        totalBreak += dayBreakSecs;
        totalNet += dayNetSecs;
        totalTask += dayTaskSecs;
        totalOvertime += dayOvertimeSecs;

        const dayName = getDayOfWeek(dKey);
        let status = 'Absent';
        if (dayNetSecs >= 6 * 3600) status = 'Present';
        else if (dayNetSecs > 0) status = 'Half Day';
        else if (dayName === 'Sunday') status = 'Weekend';

        entries.push({
            date: dKey,
            dayName,
            clockInAt: earliestIn,
            clockOutAt: latestOut,
            grossShiftSeconds: dayGrossSecs,
            breakSeconds: dayBreakSecs,
            netWorkedSeconds: dayNetSecs,
            taskWorkedSeconds: dayTaskSecs,
            idleSeconds: dayIdleSecs,
            overtimeSeconds: dayOvertimeSecs,
            ordersWorked: dayTaskLogs,
            status,
            notes: dayAttendance.map(a => a.notes).filter(Boolean).join(' | ')
        });

        curr.setDate(curr.getDate() + 1);
    }

    const totalIdle = Math.max(0, totalNet - totalTask);
    const productivityPercentage = totalNet > 0 ? Math.min(100, Math.round((totalTask / totalNet) * 100)) : 0;

    res.json({
        timesheetId: existingTimesheet?._id || null,
        status: existingTimesheet?.status || 'Draft',
        submittedAt: existingTimesheet?.submittedAt || null,
        submissionNotes: existingTimesheet?.submissionNotes || '',
        reviewedBy: existingTimesheet?.reviewedBy || null,
        reviewedAt: existingTimesheet?.reviewedAt || null,
        reviewNotes: existingTimesheet?.reviewNotes || '',
        periodType,
        startDate,
        endDate,
        entries,
        totalGrossSeconds: totalGross,
        totalBreakSeconds: totalBreak,
        totalNetWorkedSeconds: totalNet,
        totalTaskSeconds: totalTask,
        totalIdleSeconds: totalIdle,
        totalOvertimeSeconds: totalOvertime,
        productivityPercentage
    });
});

// @desc    Submit timesheet for PM/Admin approval
// @route   POST /api/timesheets/submit
// @access  Private
const submitTimesheet = asyncHandler(async (req, res) => {
    const employeeId = req.user._id;
    const {
        startDate,
        endDate,
        periodType = 'weekly',
        submissionNotes = '',
        entries = [],
        totalGrossSeconds = 0,
        totalBreakSeconds = 0,
        totalNetWorkedSeconds = 0,
        totalTaskSeconds = 0,
        totalIdleSeconds = 0,
        totalOvertimeSeconds = 0,
        productivityPercentage = 0
    } = req.body;

    if (!startDate || !endDate) {
        res.status(400);
        throw new Error('Start date and end date are required');
    }

    const timesheet = await Timesheet.findOneAndUpdate(
        { employee: employeeId, startDate, endDate },
        {
            employee: employeeId,
            periodType,
            startDate,
            endDate,
            entries,
            totalGrossSeconds,
            totalBreakSeconds,
            totalNetWorkedSeconds,
            totalTaskSeconds,
            totalIdleSeconds,
            totalOvertimeSeconds,
            productivityPercentage,
            status: 'Submitted',
            submittedAt: new Date(),
            submissionNotes
        },
        { new: true, upsert: true }
    );

    res.status(200).json({
        message: 'Timesheet submitted successfully for review',
        timesheet
    });
});

// @desc    Admin / PM list all timesheets
// @route   GET /api/timesheets/admin/list
// @access  Private (Admin / PM / Employee with management role)
const getAdminTimesheets = asyncHandler(async (req, res) => {
    const { status, employeeId, startDate, endDate } = req.query;

    const filter = {};
    if (status && status !== 'All') filter.status = status;
    if (employeeId) filter.employee = employeeId;
    if (startDate && endDate) {
        filter.startDate = { $gte: startDate };
        filter.endDate = { $lte: endDate };
    }

    const timesheets = await Timesheet.find(filter)
        .populate('employee', 'name email role profilePhoto')
        .populate('reviewedBy', 'name email role')
        .sort({ submittedAt: -1, createdAt: -1 })
        .lean();

    res.json(timesheets);
});

// @desc    Approve or Reject timesheet
// @route   PUT /api/timesheets/:id/review
// @access  Private (Admin / PM)
const reviewTimesheet = asyncHandler(async (req, res) => {
    const { status, reviewNotes = '' } = req.body;

    if (!['Approved', 'Rejected'].includes(status)) {
        res.status(400);
        throw new Error('Status must be either Approved or Rejected');
    }

    const timesheet = await Timesheet.findById(req.params.id);
    if (!timesheet) {
        res.status(404);
        throw new Error('Timesheet not found');
    }

    timesheet.status = status;
    timesheet.reviewedBy = req.user._id;
    timesheet.reviewedAt = new Date();
    timesheet.reviewNotes = reviewNotes;

    await timesheet.save();

    res.json({
        message: `Timesheet ${status.toLowerCase()} successfully`,
        timesheet
    });
});

// @desc    Export consolidated timesheets data for Excel/PDF
// @route   GET /api/timesheets/admin/export
// @access  Private (Admin)
const exportTimesheetsData = asyncHandler(async (req, res) => {
    let { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
        const now = new Date();
        const start = new Date(now.getFullYear(), now.getMonth(), 1);
        const end = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        startDate = getDateKey(start);
        endDate = getDateKey(end);
    }

    const fromDate = new Date(`${startDate}T00:00:00.000Z`);
    const toDate = new Date(`${endDate}T23:59:59.999Z`);

    const employees = await User.find({ role: { $in: ['employee', 'freelancer', 'admin'] } })
        .select('name email role')
        .lean();

    const attendanceRecords = await Attendance.find({
        clockInAt: { $gte: fromDate, $lte: toDate }
    }).populate('employee', 'name email role').lean();

    const orders = await Order.find({
        'tasks.timeLogs.loggedAt': { $gte: fromDate, $lte: toDate }
    }).select('serviceName tasks').lean();

    const employeeSummary = {};

    employees.forEach(emp => {
        const empId = emp._id.toString();
        employeeSummary[empId] = {
            employeeId: empId,
            name: emp.name,
            email: emp.email,
            role: emp.role,
            totalGrossHours: 0,
            totalBreakHours: 0,
            totalNetHours: 0,
            totalTaskHours: 0,
            totalIdleHours: 0,
            totalOvertimeHours: 0,
            daysPresent: 0,
            ordersWorkedMap: {}
        };
    });

    attendanceRecords.forEach(a => {
        const empId = a.employee?._id?.toString() || a.employee?.toString();
        if (!employeeSummary[empId]) return;

        const gross = a.clockOutAt 
            ? Number(a.totalSeconds || 0) 
            : Math.max(0, Math.floor((Date.now() - new Date(a.clockInAt).getTime()) / 1000));
        const brk = Number(a.totalBreakSeconds || 0);
        const net = Math.max(0, gross - brk);

        employeeSummary[empId].totalGrossHours += gross / 3600;
        employeeSummary[empId].totalBreakHours += brk / 3600;
        employeeSummary[empId].totalNetHours += net / 3600;
        if (net > 4 * 3600) employeeSummary[empId].daysPresent += 1;
    });

    orders.forEach(order => {
        (order.tasks || []).forEach(task => {
            (task.timeLogs || []).forEach(log => {
                const empId = log.employee?.toString();
                if (!empId || !employeeSummary[empId]) return;
                const hours = Number(log.minutes || 0) / 60;
                employeeSummary[empId].totalTaskHours += hours;
                employeeSummary[empId].ordersWorkedMap[order.serviceName] = (employeeSummary[empId].ordersWorkedMap[order.serviceName] || 0) + hours;
            });
        });
    });

    const reportRows = Object.values(employeeSummary).map(emp => {
        const idle = Math.max(0, emp.totalNetHours - emp.totalTaskHours);
        const productivity = emp.totalNetHours > 0 ? Math.round((emp.totalTaskHours / emp.totalNetHours) * 100) : 0;
        return {
            ...emp,
            totalGrossHours: Number(emp.totalGrossHours.toFixed(2)),
            totalBreakHours: Number(emp.totalBreakHours.toFixed(2)),
            totalNetHours: Number(emp.totalNetHours.toFixed(2)),
            totalTaskHours: Number(emp.totalTaskHours.toFixed(2)),
            totalIdleHours: Number(idle.toFixed(2)),
            productivityPercentage: productivity,
            ordersSummary: Object.entries(emp.ordersWorkedMap).map(([s, h]) => `${s}: ${h.toFixed(1)}h`).join(', ')
        };
    });

    res.json({
        startDate,
        endDate,
        reportRows
    });
});

export {
    getMyTimesheet,
    submitTimesheet,
    getAdminTimesheets,
    reviewTimesheet,
    exportTimesheetsData
};
