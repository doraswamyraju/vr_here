import asyncHandler from 'express-async-handler';
import Lead from '../models/Lead.js';
import User from '../models/User.js';

// Helper: Pick next employee using Round-Robin assignment
const getNextAssignedEmployee = async () => {
    try {
        const employees = await User.find({ role: 'employee' }).select('_id name email phone');
        if (!employees || employees.length === 0) return null;

        // Count active leads assigned to each employee to balance load
        const leadCounts = await Lead.aggregate([
            { $match: { status: { $in: ['NEW', 'CONTACTED', 'IN_PROGRESS'] } } },
            { $group: { _id: '$assignedTo', count: { $sum: 1 } } }
        ]);

        const countMap = {};
        leadCounts.forEach(c => {
            if (c._id) countMap[c._id.toString()] = c.count;
        });

        // Pick employee with the lowest active lead load
        employees.sort((a, b) => {
            const countA = countMap[a._id.toString()] || 0;
            const countB = countMap[b._id.toString()] || 0;
            return countA - countB;
        });

        return employees[0]._id;
    } catch (err) {
        console.error('Round-robin assignment error:', err);
        return null;
    }
};

// @desc    Track Telemetry Lead from iOS / Android / Web (Category A or B)
// @route   POST /api/leads/telemetry
// @access  Public (Guest or Authenticated)
export const trackTelemetryLead = asyncHandler(async (req, res) => {
    const {
        customerId,
        customerName,
        email,
        phone,
        serviceId,
        serviceName,
        packageName,
        price,
        category = 'PAGE_VIEW', // 'PAGE_VIEW' or 'PACKAGE_CLICK'
        source = 'web', // 'ios', 'android', 'web'
        deviceInfo
    } = req.body;

    if (!serviceId || !serviceName) {
        res.status(400);
        throw new Error('Service ID and Service Name are required');
    }

    const effectiveCustomerId = req.user?._id || customerId || null;
    const effectiveName = req.user?.name || customerName || 'Guest Prospect';
    const effectiveEmail = (req.user?.email || email || '').toLowerCase().trim();
    const effectivePhone = (req.user?.phone || phone || '').trim();

    // Check for recent active lead for this user/contact & service within the last 24 hours
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const queryConditions = [{ serviceId }, { createdAt: { $gte: oneDayAgo } }];

    if (effectiveCustomerId) {
        queryConditions.push({ customerId: effectiveCustomerId });
    } else if (effectiveEmail) {
        queryConditions.push({ email: effectiveEmail });
    } else if (effectivePhone) {
        queryConditions.push({ phone: effectivePhone });
    }

    let existingLead = null;
    if (queryConditions.length > 2) {
        existingLead = await Lead.findOne({ $and: queryConditions });
    }

    if (existingLead) {
        // Upgrade lead if user transitions from Category A (PAGE_VIEW) to Category B (PACKAGE_CLICK)
        if (category === 'PACKAGE_CLICK') {
            existingLead.category = 'PACKAGE_CLICK';
            existingLead.priority = 'HIGH';
            if (packageName) existingLead.packageName = packageName;
            if (price) existingLead.price = price;
        }

        // Update contact details if guest is now known
        if (!existingLead.customerId && effectiveCustomerId) existingLead.customerId = effectiveCustomerId;
        if ((!existingLead.customerName || existingLead.customerName === 'Guest Prospect') && effectiveName) {
            existingLead.customerName = effectiveName;
        }
        if (!existingLead.email && effectiveEmail) existingLead.email = effectiveEmail;
        if (!existingLead.phone && effectivePhone) existingLead.phone = effectivePhone;

        existingLead.lastActivityAt = new Date();
        if (deviceInfo) existingLead.deviceInfo = deviceInfo;

        await existingLead.save();
        return res.status(200).json({ success: true, lead: existingLead, isNew: false });
    }

    // New Lead creation with auto round-robin employee assignment
    const assignedTo = await getNextAssignedEmployee();
    const priority = category === 'PACKAGE_CLICK' ? 'HIGH' : 'MEDIUM';

    const newLead = await Lead.create({
        customerId: effectiveCustomerId,
        customerName: effectiveName,
        email: effectiveEmail,
        phone: effectivePhone,
        serviceId,
        serviceName,
        packageName: packageName || null,
        price: Number(price) || 0,
        category,
        source,
        deviceInfo: deviceInfo || '',
        assignedTo,
        status: 'NEW',
        priority,
        lastActivityAt: new Date()
    });

    const populatedLead = await Lead.findById(newLead._id)
        .populate('assignedTo', 'name email phone')
        .populate('customerId', 'name email phone');

    res.status(201).json({ success: true, lead: populatedLead, isNew: true });
});

// @desc    Get all leads with filters & search
// @route   GET /api/leads
// @access  Private (Admin & Employee)
export const getLeads = asyncHandler(async (req, res) => {
    const {
        category,
        status,
        source,
        assignedTo,
        search,
        page = 1,
        limit = 50
    } = req.query;

    const query = {};

    // Role-based visibility: Employees only see their own assigned leads, Admins see all
    if (req.user.role === 'employee') {
        query.assignedTo = req.user._id;
    } else if (assignedTo) {
        query.assignedTo = assignedTo;
    }

    if (category) query.category = category;
    if (status) query.status = status;
    if (source) query.source = source;

    if (search) {
        query.$or = [
            { customerName: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
            { phone: { $regex: search, $options: 'i' } },
            { serviceName: { $regex: search, $options: 'i' } },
            { packageName: { $regex: search, $options: 'i' } }
        ];
    }

    const skip = (Number(page) - 1) * Number(limit);

    const totalLeads = await Lead.countDocuments(query);
    const leads = await Lead.find(query)
        .sort({ lastActivityAt: -1, createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .populate('assignedTo', 'name email phone')
        .populate('customerId', 'name email phone');

    res.json({
        leads,
        page: Number(page),
        pages: Math.ceil(totalLeads / Number(limit)),
        total: totalLeads
    });
});

// @desc    Get Lead Statistics Dashboard
// @route   GET /api/leads/stats
// @access  Private (Admin & Employee)
export const getLeadStats = asyncHandler(async (req, res) => {
    const filter = {};
    if (req.user.role === 'employee') {
        filter.assignedTo = req.user._id;
    }

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const [
        total,
        pageViews,
        packageClicks,
        converted,
        todayCount,
        iosCount,
        androidCount,
        webCount
    ] = await Promise.all([
        Lead.countDocuments(filter),
        Lead.countDocuments({ ...filter, category: 'PAGE_VIEW' }),
        Lead.countDocuments({ ...filter, category: 'PACKAGE_CLICK' }),
        Lead.countDocuments({ ...filter, status: 'CONVERTED' }),
        Lead.countDocuments({ ...filter, createdAt: { $gte: todayStart } }),
        Lead.countDocuments({ ...filter, source: 'ios' }),
        Lead.countDocuments({ ...filter, source: 'android' }),
        Lead.countDocuments({ ...filter, source: 'web' })
    ]);

    const conversionRate = total > 0 ? ((converted / total) * 100).toFixed(1) : '0.0';

    res.json({
        total,
        pageViews,
        packageClicks,
        converted,
        todayCount,
        conversionRate,
        sources: {
            ios: iosCount,
            android: androidCount,
            web: webCount
        }
    });
});

// @desc    Update Lead (Status, Notes, Reassign)
// @route   PUT /api/leads/:id
// @access  Private (Admin & Employee)
export const updateLead = asyncHandler(async (req, res) => {
    const lead = await Lead.findById(req.params.id);

    if (!lead) {
        res.status(404);
        throw new Error('Lead not found');
    }

    // Permission check: Employees can only edit their assigned leads
    if (req.user.role === 'employee' && lead.assignedTo?.toString() !== req.user._id.toString()) {
        res.status(403);
        throw new Error('Unauthorized to update this lead');
    }

    const { status, priority, assignedTo, note } = req.body;

    if (status) lead.status = status;
    if (priority) lead.priority = priority;
    if (assignedTo && req.user.role === 'admin') lead.assignedTo = assignedTo;

    if (note && note.trim()) {
        lead.notes.push({
            author: req.user.name,
            authorRole: req.user.role,
            text: note.trim(),
            createdAt: new Date()
        });
    }

    lead.lastActivityAt = new Date();
    await lead.save();

    const updated = await Lead.findById(lead._id)
        .populate('assignedTo', 'name email phone')
        .populate('customerId', 'name email phone');

    res.json(updated);
});

// @desc    Delete Lead
// @route   DELETE /api/leads/:id
// @access  Private (Admin only)
export const deleteLead = asyncHandler(async (req, res) => {
    const lead = await Lead.findById(req.params.id);
    if (!lead) {
        res.status(404);
        throw new Error('Lead not found');
    }
    await lead.deleteOne();
    res.json({ message: 'Lead deleted successfully' });
});
