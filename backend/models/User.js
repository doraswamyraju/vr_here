import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: false
    },
    googleId: {
        type: String,
        sparse: true,
        default: null
    },
    authProvider: {
        type: String,
        enum: ['local', 'google'],
        default: 'local'
    },
    phone: {
        type: String,
        required: false
    },
    profilePhoto: {
        type: String,
        default: null
    },
    companyLogo: {
        type: String,
        default: null
    },
    companyName: {
        type: String,
        default: ''
    },
    businessType: {
        type: String,
        default: ''
    },
    gstin: {
        type: String,
        default: ''
    },
    panNumber: {
        type: String,
        default: ''
    },
    address: {
        type: String,
        default: ''
    },
    role: {
        type: String,
        enum: ['admin', 'employee', 'client', 'partner', 'freelancer'],
        default: 'client'
    },
    assignedTicketCategories: {
        type: [String],
        enum: ['Technical', 'Service', 'Support'],
        default: []
    },
    skills: {
        type: [String],
        default: []
    },
    yearsOfExperience: {
        type: Number,
        default: 0
    },
    resumeUrl: {
        type: String,
        default: null
    },
    isClockedIn: {
        type: Boolean,
        default: false
    },
    lastClockInTime: {
        type: Date,
        default: null
    },
    activeOrderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        default: null
    },
    panCard: {
        type: String,
        sparse: true, // Only unique for non-null values
        default: null
    },
    commissionPercentage: {
        type: Number,
        default: 10
    },
    bankDetails: {
        accountName: { type: String, default: '' },
        accountNumber: { type: String, default: '' },
        ifscCode: { type: String, default: '' },
        bankName: { type: String, default: '' }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    canManageCompliance: {
        type: Boolean,
        default: false
    },
    pendingProfileUpdate: {
        type: {
            name: String,
            phone: String,
            skills: [String],
            yearsOfExperience: Number,
            resumeUrl: String,
            panCard: String,
            bankDetails: {
                accountName: String,
                accountNumber: String,
                ifscCode: String,
                bankName: String
            }
        },
        default: null
    },
    fcmToken: {
        type: String,
        default: null
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
}, {
    timestamps: true
});

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
    if (!this.password) return false;
    return await bcrypt.compare(enteredPassword, this.password);
};

// Encrypt password using bcrypt
userSchema.pre('save', async function (next) {
    if (!this.isModified('password') || !this.password) {
        return next();
    }

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

const User = mongoose.model('User', userSchema);

export default User;
