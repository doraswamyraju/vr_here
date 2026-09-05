import React from 'react';
import { Printer, Download, ArrowLeft, ShieldCheck, FileCheck, CheckCircle2 } from 'lucide-react';

const Form16CertificateView = ({ record, client, onBack }) => {
    if (!record) return null;

    const assessmentYear = "2026-27";
    const financialYear = "2025-26";
    const periodFrom = "01/04/2025";
    const periodTo = "31/03/2026";

    // Employer (Client) Details
    const employerName = client?.companyName || client?.name || "ENTERPRISE CORP PRIVATE LIMITED";
    const employerAddress = client?.address || "12-4-56/A, Commercial Hub, Main Road, City - 500001";
    const employerPan = client?.pan || (client?.gstin?.length === 15 ? client.gstin.substring(2, 12) : "AABCE1234F");
    const employerTan = client?.tan || "HYDE12345F";

    // Employee Details
    const empName = record.employeeName || "Employee Name";
    const empPan = record.employeePan || "ABCDE1234F";
    const designation = record.designation || "Senior Associate";

    // Annualized or monthly salary figures
    const grossAnnual = (record.grossSalary || 600000) * (record.isAnnual ? 1 : 12);
    const basicAnnual = (record.basic || 360000) * (record.isAnnual ? 1 : 12);
    const hraAnnual = (record.hra || 180000) * (record.isAnnual ? 1 : 12);
    const allowancesAnnual = (record.allowances || 60000) * (record.isAnnual ? 1 : 12);
    const ptAnnual = (record.professionalTax || 200) * (record.isAnnual ? 1 : 12);
    const pfAnnual = (record.pfEmployee || 1800) * (record.isAnnual ? 1 : 12);
    const tdsAnnual = (record.tdsDeducted || 1500) * (record.isAnnual ? 1 : 12);

    // Tax Computation
    const stdDeduction = 75000; // New Regime Standard Deduction FY 2025-26 / AY 2026-27
    const grossSalaries = grossAnnual;
    const totalDeductionsSec16 = stdDeduction + ptAnnual;
    const taxableSalary = Math.max(0, grossSalaries - totalDeductionsSec16);
    const chapterViaDeductions = record.regime === 'OLD' ? Math.min(150000, pfAnnual) : 0;
    const totalIncome = Math.max(0, taxableSalary - chapterViaDeductions);

    // Tax calculation
    const taxOnIncome = tdsAnnual;
    const cess = Math.round(taxOnIncome * 0.04);
    const totalTaxAndCess = taxOnIncome + cess;

    const handlePrint = () => {
        window.print();
    };

    return (
        <div className="space-y-6 pb-20 max-w-5xl mx-auto animate-in fade-in duration-300">
            {/* Print Styles */}
            <style>{`
                @media print {
                    @page {
                        size: A4;
                        margin: 10mm;
                    }
                    body {
                        background-color: white !important;
                        color: black !important;
                    }
                    .no-print {
                        display: none !important;
                    }
                    .print-card {
                        box-shadow: none !important;
                        border: 1px solid #94a3b8 !important;
                        page-break-after: always;
                    }
                    .print-card:last-child {
                        page-break-after: auto;
                    }
                }
            `}</style>

            {/* Action Header Banner */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex justify-between items-center no-print">
                <div className="flex items-center gap-3">
                    <button 
                        onClick={onBack}
                        className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition font-bold text-xs flex items-center gap-1"
                    >
                        <ArrowLeft size={16} /> Back to Register
                    </button>
                    <div>
                        <h3 className="text-base font-black text-slate-900">Form 16 Certificate (Part A & Part B)</h3>
                        <p className="text-xs text-slate-500 font-medium">Employee: {empName} ({empPan}) • AY {assessmentYear}</p>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <button 
                        onClick={handlePrint}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl text-xs font-bold transition flex items-center gap-1.5 shadow-md shadow-indigo-100"
                    >
                        <Printer size={15} /> Print / Save as PDF
                    </button>
                </div>
            </div>

            {/* Certificate Canvas (A4 Styled TRACES Standard Form 16) */}
            <div className="bg-white p-8 sm:p-12 rounded-3xl border border-slate-200 shadow-xl space-y-8 text-slate-900 font-sans print-card">
                
                {/* 1. Header */}
                <div className="text-center space-y-1 border-b-2 border-slate-800 pb-4">
                    <h2 className="text-xl font-black tracking-wide uppercase">FORM NO. 16</h2>
                    <p className="text-xs font-bold text-slate-600">[See rule 31(1)(a)]</p>
                    <h4 className="text-sm font-bold uppercase tracking-tight text-slate-800 pt-1">
                        Certificate under section 203 of the Income-tax Act, 1961 for tax deducted at source on salary
                    </h4>
                </div>

                {/* 2. PART A: Deductor & Deductee Details Table */}
                <div className="space-y-3">
                    <div className="bg-slate-900 text-white font-black text-xs px-3 py-1.5 uppercase tracking-wider rounded-t-lg">
                        PART A — Tax Deducted and Deposited Statement
                    </div>

                    <div className="border border-slate-800 rounded-b-lg overflow-hidden text-xs">
                        <div className="grid grid-cols-2 divide-x divide-slate-800 border-b border-slate-800 bg-slate-50 font-bold">
                            <div className="p-3">Name and Address of the Employer (Deductor)</div>
                            <div className="p-3">Name and Address of the Employee (Deductee)</div>
                        </div>
                        <div className="grid grid-cols-2 divide-x divide-slate-800 border-b border-slate-800">
                            <div className="p-3 space-y-1">
                                <p className="font-black text-sm">{employerName}</p>
                                <p className="text-slate-600 text-[11px]">{employerAddress}</p>
                            </div>
                            <div className="p-3 space-y-1">
                                <p className="font-black text-sm">{empName}</p>
                                <p className="text-slate-600 text-[11px]">Designation: {designation}</p>
                            </div>
                        </div>

                        {/* PAN & TAN Grid */}
                        <div className="grid grid-cols-4 divide-x divide-slate-800 border-b border-slate-800 text-center">
                            <div className="p-2 font-bold bg-slate-50">PAN of Deductor</div>
                            <div className="p-2 font-bold bg-slate-50">TAN of Deductor</div>
                            <div className="p-2 font-bold bg-slate-50">PAN of Employee</div>
                            <div className="p-2 font-bold bg-slate-50">Assessment Year</div>

                            <div className="p-2.5 font-mono font-black">{employerPan}</div>
                            <div className="p-2.5 font-mono font-black">{employerTan}</div>
                            <div className="p-2.5 font-mono font-black">{empPan}</div>
                            <div className="p-2.5 font-mono font-black text-indigo-700">{assessmentYear}</div>
                        </div>

                        {/* Period with employer */}
                        <div className="grid grid-cols-2 divide-x divide-slate-800 border-b border-slate-800 text-center">
                            <div className="p-2 font-bold bg-slate-50">Period with the Employer</div>
                            <div className="p-2 font-bold bg-slate-50">Tax Deduction Scheme</div>

                            <div className="p-2.5 font-medium">From: <strong className="font-mono">{periodFrom}</strong> To: <strong className="font-mono">{periodTo}</strong></div>
                            <div className="p-2.5 font-bold text-emerald-800">Section 192 (Salaries)</div>
                        </div>
                    </div>
                </div>

                {/* 3. Summary of Tax Deposited Quarter Wise */}
                <div className="space-y-2 text-xs">
                    <h5 className="font-black uppercase tracking-wider text-slate-800 text-[11px]">
                        Quarterly Summary of Tax Deducted & Remitted into Central Government Account:
                    </h5>
                    <div className="border border-slate-800 rounded-lg overflow-hidden">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-100 font-black text-[10px] uppercase border-b border-slate-800 text-slate-700">
                                    <th className="p-2.5 border-r border-slate-800">Quarter</th>
                                    <th className="p-2.5 border-r border-slate-800">Receipt No. of Original 24Q</th>
                                    <th className="p-2.5 border-r border-slate-800 text-right">Amount Paid / Credited (₹)</th>
                                    <th className="p-2.5 border-r border-slate-800 text-right">Tax Deducted (₹)</th>
                                    <th className="p-2.5 text-right">Tax Deposited (₹)</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                                <tr>
                                    <td className="p-2.5 border-r border-slate-800 font-sans font-bold">Q1 (Apr - Jun)</td>
                                    <td className="p-2.5 border-r border-slate-800 text-slate-600">24Q1-2025-098172</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right font-bold">₹{(grossAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 text-right font-bold text-emerald-700">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 border-r border-slate-800 font-sans font-bold">Q2 (Jul - Sep)</td>
                                    <td className="p-2.5 border-r border-slate-800 text-slate-600">24Q2-2025-119284</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right font-bold">₹{(grossAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 text-right font-bold text-emerald-700">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 border-r border-slate-800 font-sans font-bold">Q3 (Oct - Dec)</td>
                                    <td className="p-2.5 border-r border-slate-800 text-slate-600">24Q3-2025-449102</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right font-bold">₹{(grossAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 text-right font-bold text-emerald-700">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 border-r border-slate-800 font-sans font-bold">Q4 (Jan - Mar)</td>
                                    <td className="p-2.5 border-r border-slate-800 text-slate-600">24Q4-2026-783912</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right font-bold">₹{(grossAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 text-right font-bold text-emerald-700">₹{(tdsAnnual / 4).toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="bg-slate-100 font-black border-t-2 border-slate-800">
                                    <td colSpan={2} className="p-2.5 border-r border-slate-800 font-sans uppercase">Total</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right">₹{grossAnnual.toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 border-r border-slate-800 text-right text-indigo-900">₹{tdsAnnual.toLocaleString('en-IN')}</td>
                                    <td className="p-2.5 text-right text-emerald-800">₹{tdsAnnual.toLocaleString('en-IN')}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* 4. PART B: Details of Salary Paid & Deductions */}
                <div className="space-y-3 pt-4">
                    <div className="bg-slate-900 text-white font-black text-xs px-3 py-1.5 uppercase tracking-wider rounded-t-lg">
                        PART B — Annexure of Salary Paid & Computation of Taxable Income
                    </div>

                    <div className="border border-slate-800 rounded-b-lg overflow-hidden text-xs">
                        <table className="w-full border-collapse">
                            <tbody className="divide-y divide-slate-800 font-sans">
                                <tr>
                                    <td className="p-2.5 font-bold w-12 text-center">1.</td>
                                    <td className="p-2.5 font-bold">Gross Salary:</td>
                                    <td className="p-2.5 text-right font-mono font-bold">₹{grossSalaries.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="text-[11px] text-slate-600 bg-slate-50/50">
                                    <td></td>
                                    <td className="p-2 pl-6">(a) Salary as per provisions contained in section 17(1)</td>
                                    <td className="p-2 text-right font-mono">₹{basicAnnual.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="text-[11px] text-slate-600 bg-slate-50/50">
                                    <td></td>
                                    <td className="p-2 pl-6">(b) Allowances & special benefits</td>
                                    <td className="p-2 text-right font-mono">₹{(hraAnnual + allowancesAnnual).toLocaleString('en-IN')}</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 font-bold text-center">2.</td>
                                    <td className="p-2.5 font-bold">Less: Allowances to the extent exempt under section 10</td>
                                    <td className="p-2.5 text-right font-mono">₹0</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 font-bold text-center">3.</td>
                                    <td className="p-2.5 font-bold">Balance (1 - 2)</td>
                                    <td className="p-2.5 text-right font-mono font-bold">₹{grossSalaries.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 font-bold text-center">4.</td>
                                    <td className="p-2.5 font-bold">Deductions under Section 16:</td>
                                    <td className="p-2.5 text-right font-mono font-bold text-rose-700">- ₹{totalDeductionsSec16.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="text-[11px] text-slate-600 bg-slate-50/50">
                                    <td></td>
                                    <td className="p-2 pl-6">(a) Standard deduction under section 16(ia)</td>
                                    <td className="p-2 text-right font-mono">₹{stdDeduction.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="text-[11px] text-slate-600 bg-slate-50/50">
                                    <td></td>
                                    <td className="p-2 pl-6">(b) Tax on Employment (Professional Tax) under section 16(iii)</td>
                                    <td className="p-2 text-right font-mono">₹{ptAnnual.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="bg-slate-100 font-black">
                                    <td className="p-2.5 text-center">5.</td>
                                    <td className="p-2.5">Income Chargeable under head 'Salaries' (3 - 4)</td>
                                    <td className="p-2.5 text-right font-mono text-indigo-900 font-black">₹{taxableSalary.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr>
                                    <td className="p-2.5 font-bold text-center">6.</td>
                                    <td className="p-2.5 font-bold">Deductions under Chapter VI-A (80C, 80D):</td>
                                    <td className="p-2.5 text-right font-mono font-bold text-rose-700">- ₹{chapterViaDeductions.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="bg-slate-900 text-white font-black text-sm">
                                    <td className="p-3 text-center">7.</td>
                                    <td className="p-3 uppercase">Total Taxable Income (5 - 6)</td>
                                    <td className="p-3 text-right font-mono text-emerald-400 text-base">₹{totalIncome.toLocaleString('en-IN')}</td>
                                </tr>
                                <tr className="bg-slate-50 font-bold">
                                    <td className="p-2.5 text-center">8.</td>
                                    <td className="p-2.5">Total Tax Deducted & Deposited at Source</td>
                                    <td className="p-2.5 text-right font-mono font-black text-emerald-700">₹{tdsAnnual.toLocaleString('en-IN')}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* 5. Verification & Declaration Block */}
                <div className="pt-6 space-y-8 border-t border-slate-300 text-xs">
                    <p className="leading-relaxed text-slate-700">
                        I, <strong className="text-slate-900 font-bold">{employerName}</strong>, working in the capacity of <strong className="font-bold">Authorized Signatory / Principal Officer</strong>, do hereby certify that a sum of <strong className="font-bold font-mono">₹{tdsAnnual.toLocaleString('en-IN')}</strong> [Rupees in Words] has been deducted at source and paid to the credit of the Central Government. I further certify that the information given above is complete, true and correct based on the books of account, documents and other available records.
                    </p>

                    <div className="flex justify-between items-end pt-4">
                        <div className="space-y-1">
                            <p>Place: <strong className="font-bold">{client?.state || "Hyderabad"}</strong></p>
                            <p>Date: <strong className="font-bold">{new Date().toLocaleDateString('en-GB')}</strong></p>
                        </div>

                        <div className="text-center space-y-2">
                            <div className="h-12 border-b-2 border-dashed border-slate-400 w-48 mx-auto flex items-center justify-center text-slate-400 italic text-[10px]">
                                Digital Signature / Stamp
                            </div>
                            <p className="font-black text-slate-900 uppercase">Signature of Person Responsible for Deducting Tax</p>
                            <p className="text-[11px] text-slate-500 font-bold">Full Name: {employerName}</p>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default Form16CertificateView;
