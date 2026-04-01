import asyncHandler from 'express-async-handler';
import RecurringService from '../models/RecurringService.js';
import Notification from '../models/Notification.js';
import User from '../models/User.js';

import { calculateNextRunDate } from '../utils/dateUtils.js';
import { generateOrderFromSubscription } from '../utils/automationUtils.js';

// Internal function to create a subscription
const createSubscriptionInternal = async (data) => {
    const {
        userId,
        clientName,
        serviceName,
        packageName,
        price,
        frequency,
        dayOfMonth,
        dayOfWeek,
        startDate,
        assignedEmployee,
        assignedMaker,
        assignedChecker,
        tasksTemplate,
        requirementsTemplate,
        checklistsTemplate
    } = data;

    const subscription = new RecurringService({
        user: userId,
        clientName,
        serviceName,
        packageName,
        price,
        frequency,
        dayOfMonth: dayOfMonth || 1,
        dayOfWeek: dayOfWeek || 1,
        startDate: startDate || new Date(),
        nextRunDate: calculateNextRunDate(frequency, dayOfMonth || 1, dayOfWeek || 1, startDate || new Date()),
        assignedEmployee,
        assignedMaker,
        assignedChecker,
        tasksTemplate: tasksTemplate || [],
        requirementsTemplate: requirementsTemplate || [],
        checklistsTemplate: checklistsTemplate || []
    });

    const savedSubscription = await subscription.save();

    // Check if it should run IMMEDIATELY (e.g., if today is the scheduled day)
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const scheduledDate = new Date(savedSubscription.nextRunDate);
    scheduledDate.setHours(0, 0, 0, 0);

    if (scheduledDate <= today) {
        console.log(`[Automation] Triggering immediate first-run for subscription ${savedSubscription._id}`);
        // Populate for automation
        const populatedSub = await RecurringService.findById(savedSubscription._id)
            .populate('user', 'name email phone')
            .populate('assignedEmployee', 'name email role')
            .populate('assignedMaker', 'name email role')
            .populate('assignedChecker', 'name email role');
            
        await generateOrderFromSubscription(populatedSub);
    }

    return savedSubscription;
};

// @desc    Create new recurring service
// @route   POST /api/recurring
// @access  Private/Admin
const createSubscription = asyncHandler(async (req, res) => {
    const createdSubscription = await createSubscriptionInternal(req.body);
    res.status(201).json(createdSubscription);
});

// @desc    Get all subscriptions
// @route   GET /api/recurring
// @access  Private/Admin
const getSubscriptions = asyncHandler(async (req, res) => {
    const subscriptions = await RecurringService.find({})
        .populate('user', 'name email phone')
        .populate('assignedEmployee', 'name email role')
        .populate('assignedMaker', 'name email role')
        .populate('assignedChecker', 'name email role');
    res.json(subscriptions);
});

// @desc    Get subscription by ID
// @route   GET /api/recurring/:id
// @access  Private/Admin
const getSubscriptionById = asyncHandler(async (req, res) => {
    const subscription = await RecurringService.findById(req.params.id)
        .populate('user', 'name email phone')
        .populate('assignedEmployee', 'name email role')
        .populate('assignedMaker', 'name email role')
        .populate('assignedChecker', 'name email role');

    if (subscription) {
        res.json(subscription);
    } else {
        res.status(404);
        throw new Error('Subscription not found');
    }
});

// @desc    Update subscription
// @route   PUT /api/recurring/:id
// @access  Private/Admin
const updateSubscription = asyncHandler(async (req, res) => {
    const subscription = await RecurringService.findById(req.params.id);

    if (subscription) {
        subscription.frequency = req.body.frequency || subscription.frequency;
        subscription.dayOfMonth = req.body.dayOfMonth ?? subscription.dayOfMonth;
        subscription.dayOfWeek = req.body.dayOfWeek ?? subscription.dayOfWeek;
        subscription.isActive = req.body.isActive ?? subscription.isActive;
        subscription.assignedEmployee = req.body.assignedEmployee ?? subscription.assignedEmployee;
        subscription.assignedMaker = req.body.assignedMaker ?? subscription.assignedMaker;
        subscription.assignedChecker = req.body.assignedChecker ?? subscription.assignedChecker;
        subscription.serviceName = req.body.serviceName || subscription.serviceName;
        subscription.packageName = req.body.packageName || subscription.packageName;
        subscription.price = req.body.price ?? subscription.price;

        if (req.body.frequency || req.body.dayOfMonth !== undefined || req.body.dayOfWeek !== undefined) {
             subscription.nextRunDate = calculateNextRunDate(subscription.frequency, subscription.dayOfMonth, subscription.dayOfWeek);
        }

        const updatedSubscription = await subscription.save();
        res.json(updatedSubscription);
    } else {
        res.status(404);
        throw new Error('Subscription not found');
    }
});

// @desc    Delete subscription
// @route   DELETE /api/recurring/:id
// @access  Private/Admin
const deleteSubscription = asyncHandler(async (req, res) => {
    const subscription = await RecurringService.findById(req.params.id);

    if (subscription) {
        await subscription.deleteOne();
        res.json({ message: 'Subscription removed' });
    } else {
        res.status(404);
        throw new Error('Subscription not found');
    }
});

export {
    createSubscription,
    createSubscriptionInternal,
    getSubscriptions,
    getSubscriptionById,
    updateSubscription,
    deleteSubscription,
    calculateNextRunDate
};
