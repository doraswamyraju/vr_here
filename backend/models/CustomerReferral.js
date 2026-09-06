import mongoose from 'mongoose';

const customerReferralSchema = new mongoose.Schema({
    referrer: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    referee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    refereeName: {
        type: String,
        required: true
    },
    refereePhone: {
        type: String,
        required: true,
        index: true
    },
    refereeEmail: {
        type: String,
        default: ''
    },
    interestedService: {
        type: String,
        default: 'General Compliance / Registration'
    },
    status: {
        type: String,
        enum: ['Invited', 'Registered', 'Order_Placed', 'Rewarded'],
        default: 'Invited'
    },
    rewardAmount: {
        type: Number,
        default: 500
    },
    rewardClaimedVia: {
        type: String,
        enum: ['Service_Credit', 'UPI_Payout', 'Unclaimed'],
        default: 'Unclaimed'
    },
    payoutUpi: {
        type: String,
        default: ''
    },
    order: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        default: null
    },
    orderAmount: {
        type: Number,
        default: 0
    },
    rewardedAt: {
        type: Date,
        default: null
    },
    payoutRequestedAt: {
        type: Date,
        default: null
    },
    payoutStatus: {
        type: String,
        enum: ['None', 'Pending', 'Paid', 'Rejected'],
        default: 'None'
    },
    payoutNotes: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

customerReferralSchema.index({ referrer: 1, refereePhone: 1 });

const CustomerReferral = mongoose.model('CustomerReferral', customerReferralSchema);

export default CustomerReferral;
