import mongoose from 'mongoose';

const payrollSchema = new mongoose.Schema({
    clientUser: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    financialYear: {
        type: String,
        default: '2025-2026'
    },
    month: {
        type: String, // e.g. "April 2026", "May 2026"
        required: true
    },
    employeeName: {
        type: String,
        required: true
    },
    employeePan: {
        type: String,
        required: true
    },
    designation: {
        type: String,
        default: ''
    },
    taxRegime: {
        type: String,
        enum: ['NEW', 'OLD'],
        default: 'NEW'
    },
    // Earnings
    basic: { type: Number, default: 0 },
    hra: { type: Number, default: 0 },
    allowances: { type: Number, default: 0 },
    grossSalary: { type: Number, required: true },
    
    // Deductions
    pfEmployee: { type: Number, default: 0 },
    esiEmployee: { type: Number, default: 0 },
    professionalTax: { type: Number, default: 0 },
    tdsDeducted: { type: Number, default: 0 },
    totalDeductions: { type: Number, default: 0 },
    
    netPayable: { type: Number, required: true },
    status: {
        type: String,
        enum: ['Draft', 'Processed', 'Paid'],
        default: 'Processed'
    },
    paymentDate: Date,
    remarks: String
}, { timestamps: true });

export default mongoose.model('Payroll', payrollSchema);
