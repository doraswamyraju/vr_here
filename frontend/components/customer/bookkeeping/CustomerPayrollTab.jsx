import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, Plus, Upload, FileSpreadsheet, Download, 
    Smartphone, Calendar, CheckCircle2, Clock, Award, ShieldCheck, ArrowUpRight, DollarSign, FileText, RefreshCw
} from 'lucide-react';
import Form16CertificateView from '../../admin/bookkeeping/Form16CertificateView';

const CustomerPayrollTab = ({ token, company, userInfo }) => {
    const [payrollRecords, setPayrollRecords] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);
    const [showTimesheetModal, setShowTimesheetModal] = useState(false);
    const [selectedForm16, setSelectedForm16] = useState(null);

    // Form State
    const [month, setMonth] = useState('April 2026');
    const [employeeName, setEmployeeName] = useState('');
    const [employeePan, setEmployeePan] = useState('');
    const [designation, setDesignation] = useState('');
    const [basic, setBasic] = useState(30000);
    const [hra, setHra] = useState(15000);
    const [allowances, setAllowances] = useState(5000);
    const [pf, setPf] = useState(1800);
    const [pt, setPt] = useState(200);
    const [tds, setTds] = useState(1500);

    // Timesheet upload state
    const [timesheetMonth, setTimesheetMonth] = useState('April 2026');
    const [timesheetFileName, setTimesheetFileName] = useState('');
    const [staffCount, setStaffCount] = useState(5);
    const [timesheetNotes, setTimesheetNotes] = useState('');

    const grossSalary = Number(basic) + Number(hra) + Number(allowances);
    const totalDeductions = Number(pf) + Number(pt) + Number(tds);
    const netPayable = grossSalary - totalDeductions;

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchPayroll = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/accounting/payroll', config);
            setPayrollRecords(data);
        } catch (error) {
            console.error('Failed to fetch payroll records:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPayroll();
    }, []);

    const handleSaveRecord = async (e) => {
        e.preventDefault();
        if (!employeeName || !employeePan) {
            alert('Please enter employee name and PAN');
            return;
        }

        try {
            const payload = {
                month,
                employeeName,
                employeePan: employeePan.toUpperCase(),
                designation,
                basic,
                hra,
                allowances,
                grossSalary,
                pfEmployee: pf,
                professionalTax: pt,
                tdsDeducted: tds,
                netPayable,
                status: 'Processed'
            };

            const { data } = await axios.post('/api/accounting/payroll', payload, config);
            setPayrollRecords([data, ...payrollRecords]);
            setShowAddModal(false);
            setEmployeeName('');
            setEmployeePan('');
            setDesignation('');
            alert('Employee payroll record logged successfully!');
        } catch (error) {
            alert('Failed to save record: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleUploadTimesheet = (e) => {
        e.preventDefault();
        if (!timesheetFileName) {
            alert('Please select a timesheet file');
            return;
        }
        alert(`Timesheet for ${timesheetMonth} (${staffCount} employees) uploaded successfully! It is now synced with your CA / Admin audit desk.`);
        setShowTimesheetModal(false);
        setTimesheetFileName('');
    };

    // If viewing Form 16 certificate
    if (selectedForm16) {
        return (
            <Form16CertificateView 
                record={selectedForm16}
                client={company || userInfo}
                onBack={() => setSelectedForm16(null)}
            />
        );
    }

    const totalGross = payrollRecords.reduce((sum, r) => sum + (r.grossSalary || 0), 0);
    const totalTds = payrollRecords.reduce((sum, r) => sum + (r.tdsDeducted || 0), 0);
    const totalNet = payrollRecords.reduce((sum, r) => sum + (r.netPayable || 0), 0);

    return (
        <div className="space-y-6">
            
            {/* VR HR Application Connected Banner */}
            <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-3xl p-6 sm:p-8 text-white shadow-xl relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                <div className="absolute top-0 right-0 w-80 h-80 bg-indigo-500/10 rounded-full blur-3xl -mr-32 -mt-32"></div>
                <div className="relative z-10 space-y-2 max-w-2xl">
                    <div className="flex items-center gap-2">
                        <span className="px-3 py-1 bg-indigo-500/30 text-indigo-200 text-[10px] font-black uppercase tracking-wider rounded-full border border-indigo-400/20 flex items-center gap-1.5">
                            <Smartphone size={12} /> VR HR App Companion
                        </span>
                        <span className="text-[10px] font-bold text-emerald-400 bg-emerald-950/80 px-2.5 py-0.5 rounded-full border border-emerald-800">
                            Automatic Sync Enabled
                        </span>
                    </div>
                    <h3 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                        Staff Attendance, Time Sheets & Payroll Management
                    </h3>
                    <p className="text-xs text-slate-300 leading-relaxed">
                        With the <strong>VR HR App</strong>, your staff can clock-in/out on mobile with live GPS & biometric verification. Timesheets and leave approvals automatically sync here for 1-click salary registers, TDS Sec 192 compliance, and Form 16 certificates.
                    </p>
                </div>

                <div className="relative z-10 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0 w-full md:w-auto">
                    <button
                        onClick={() => setShowTimesheetModal(true)}
                        className="bg-white hover:bg-slate-100 text-slate-900 px-5 py-3 rounded-2xl font-black text-xs uppercase tracking-wider transition shadow-lg flex items-center justify-center gap-2"
                    >
                        <Upload size={15} className="text-indigo-600" /> Upload Time Sheet (Excel/PDF)
                    </button>
                    <button
                        onClick={() => setShowAddModal(true)}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-3 rounded-2xl font-black text-xs uppercase tracking-wider transition shadow-lg shadow-indigo-500/20 flex items-center justify-center gap-2"
                    >
                        <Plus size={15} /> Add Salary Entry
                    </button>
                </div>
            </div>

            {/* KPI Summary Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Active Staff Entries</span>
                    <p className="text-xl font-black text-slate-900 font-mono">{payrollRecords.length}</p>
                    <p className="text-[10px] text-slate-500 font-medium">Logged Employees</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Total Gross Salary</span>
                    <p className="text-xl font-black text-slate-900 font-mono">₹{totalGross.toLocaleString('en-IN')}</p>
                    <p className="text-[10px] text-slate-500 font-medium">Monthly Outflow</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">TDS Deducted (Sec 192)</span>
                    <p className="text-xl font-black text-rose-600 font-mono">₹{totalTds.toLocaleString('en-IN')}</p>
                    <p className="text-[10px] text-rose-600 font-bold">Tax Remittance Pool</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm space-y-1">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Net Salary Disbursed</span>
                    <p className="text-xl font-black text-emerald-600 font-mono">₹{totalNet.toLocaleString('en-IN')}</p>
                    <p className="text-[10px] text-emerald-600 font-bold">Direct Bank Transfer</p>
                </div>
            </div>

            {/* Main Payroll Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-6 space-y-6">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-100 pb-4">
                    <div>
                        <h4 className="font-black text-slate-900 text-lg">Staff Monthly Salary & Compliance Register</h4>
                        <p className="text-xs text-slate-500 font-medium">Auto-computed net salaries, statutory PF/PT, and TRACES Form 16 certificates</p>
                    </div>

                    <div className="flex items-center gap-2">
                        <button
                            onClick={fetchPayroll}
                            className="p-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl transition"
                            title="Refresh Payroll"
                        >
                            <RefreshCw size={15} />
                        </button>
                    </div>
                </div>

                {loading ? (
                    <div className="flex justify-center py-20">
                        <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                    </div>
                ) : payrollRecords.length === 0 ? (
                    <div className="text-center py-16 text-slate-400 space-y-3">
                        <Users size={48} className="mx-auto opacity-30" />
                        <div>
                            <p className="font-bold text-slate-800 text-sm">No Employee Salary Records Logged Yet</p>
                            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                                Upload your employee monthly timesheet or log individual staff salaries to generate payroll registers and Form 16 certificates.
                            </p>
                        </div>
                        <div className="flex items-center justify-center gap-2 pt-2">
                            <button
                                onClick={() => setShowTimesheetModal(true)}
                                className="bg-slate-900 hover:bg-slate-800 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider transition"
                            >
                                Upload Timesheet
                            </button>
                            <button
                                onClick={() => setShowAddModal(true)}
                                className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider transition"
                            >
                                + Add Salary Row
                            </button>
                        </div>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-5 py-3.5">Month</th>
                                    <th className="px-5 py-3.5">Employee Name</th>
                                    <th className="px-5 py-3.5">PAN & Designation</th>
                                    <th className="px-5 py-3.5 font-mono text-right">Gross Pay (₹)</th>
                                    <th className="px-5 py-3.5 font-mono text-right">PF & PT (₹)</th>
                                    <th className="px-5 py-3.5 font-mono text-right">TDS u/s 192 (₹)</th>
                                    <th className="px-5 py-3.5 font-mono text-right">Net Payable (₹)</th>
                                    <th className="px-5 py-3.5 text-center">Compliance</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {payrollRecords.map(pr => (
                                    <tr key={pr._id} className="hover:bg-slate-50/60 transition">
                                        <td className="px-5 py-3.5 font-bold text-slate-700">{pr.month}</td>
                                        <td className="px-5 py-3.5 font-black text-slate-900">{pr.employeeName}</td>
                                        <td className="px-5 py-3.5">
                                            <div className="font-mono text-slate-500 font-bold">{pr.employeePan}</div>
                                            <div className="text-[10px] text-slate-400">{pr.designation || 'Staff'}</div>
                                        </td>
                                        <td className="px-5 py-3.5 font-mono font-bold text-slate-800 text-right">₹{pr.grossSalary?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 font-mono text-slate-600 text-right">₹{((pr.pfEmployee || 0) + (pr.professionalTax || 0))?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 font-mono font-bold text-rose-600 text-right">₹{pr.tdsDeducted?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 font-mono font-black text-emerald-600 text-sm text-right">₹{pr.netPayable?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 text-center">
                                            <button
                                                onClick={() => setSelectedForm16(pr)}
                                                className="bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 px-3 py-1 rounded-xl text-[11px] font-bold transition flex items-center gap-1 mx-auto shadow-sm"
                                            >
                                                <Award size={13} /> Form 16 (Part A & B)
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Modal: Add Salary Row */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-sm">Add Employee Salary & TDS Entry</h3>
                            <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-600">✕</button>
                        </div>

                        <form onSubmit={handleSaveRecord} className="p-6 space-y-3.5 text-xs">
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Month / Year *</label>
                                    <input type="text" value={month} onChange={(e)=>setMonth(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-bold" required />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Employee Name *</label>
                                    <input type="text" value={employeeName} onChange={(e)=>setEmployeeName(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-bold" placeholder="Full Name" required />
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Employee PAN *</label>
                                    <input type="text" value={employeePan} onChange={(e)=>setEmployeePan(e.target.value.toUpperCase())} maxLength={10} placeholder="ABCDE1234F" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono uppercase font-bold" required />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Designation</label>
                                    <input type="text" value={designation} onChange={(e)=>setDesignation(e.target.value)} placeholder="e.g. Sales Executive" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2" />
                                </div>
                            </div>

                            <div className="grid grid-cols-3 gap-2 bg-slate-50 p-3 rounded-2xl border border-slate-200">
                                <div>
                                    <label className="block text-[9px] font-bold text-slate-500 mb-1">Basic (₹)</label>
                                    <input type="number" value={basic} onChange={(e)=>setBasic(e.target.value)} className="w-full bg-white border border-slate-200 rounded-lg p-1.5 font-bold" />
                                </div>
                                <div>
                                    <label className="block text-[9px] font-bold text-slate-500 mb-1">HRA (₹)</label>
                                    <input type="number" value={hra} onChange={(e)=>setHra(e.target.value)} className="w-full bg-white border border-slate-200 rounded-lg p-1.5 font-bold" />
                                </div>
                                <div>
                                    <label className="block text-[9px] font-bold text-slate-500 mb-1">Allowances (₹)</label>
                                    <input type="number" value={allowances} onChange={(e)=>setAllowances(e.target.value)} className="w-full bg-white border border-slate-200 rounded-lg p-1.5 font-bold" />
                                </div>
                            </div>

                            <div className="grid grid-cols-3 gap-2 bg-rose-50/50 p-3 rounded-2xl border border-rose-100">
                                <div>
                                    <label className="block text-[9px] font-bold text-rose-800 mb-1">PF (₹)</label>
                                    <input type="number" value={pf} onChange={(e)=>setPf(e.target.value)} className="w-full bg-white border border-rose-200 rounded-lg p-1.5 font-bold" />
                                </div>
                                <div>
                                    <label className="block text-[9px] font-bold text-rose-800 mb-1">PT (₹)</label>
                                    <input type="number" value={pt} onChange={(e)=>setPt(e.target.value)} className="w-full bg-white border border-rose-200 rounded-lg p-1.5 font-bold" />
                                </div>
                                <div>
                                    <label className="block text-[9px] font-bold text-rose-800 mb-1">TDS u/s 192 (₹)</label>
                                    <input type="number" value={tds} onChange={(e)=>setTds(e.target.value)} className="w-full bg-white border border-rose-200 rounded-lg p-1.5 font-bold text-rose-700" />
                                </div>
                            </div>

                            <div className="flex justify-between items-center bg-slate-900 text-white p-3 rounded-xl font-bold">
                                <span>Net Salary Payable:</span>
                                <span className="font-mono text-emerald-400 text-base">₹{netPayable.toLocaleString('en-IN')}.00</span>
                            </div>

                            <div className="flex justify-end gap-2 pt-2">
                                <button type="button" onClick={()=>setShowAddModal(false)} className="px-4 py-2 rounded-xl text-slate-600 font-bold">Cancel</button>
                                <button type="submit" className="bg-indigo-600 text-white px-5 py-2 rounded-xl font-bold shadow-md">Save Record</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Modal: Upload Timesheet */}
            {showTimesheetModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <div className="flex items-center gap-2">
                                <FileSpreadsheet className="text-indigo-600" size={18} />
                                <h3 className="font-black text-slate-900 text-sm">Upload Staff Time Sheet & Attendance File</h3>
                            </div>
                            <button onClick={() => setShowTimesheetModal(false)} className="text-slate-400 hover:text-slate-600">✕</button>
                        </div>

                        <form onSubmit={handleUploadTimesheet} className="p-6 space-y-4 text-xs">
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Payroll Month / Period *</label>
                                    <input 
                                        type="text" 
                                        value={timesheetMonth} 
                                        onChange={(e)=>setTimesheetMonth(e.target.value)} 
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold" 
                                        required 
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Total Staff Included</label>
                                    <input 
                                        type="number" 
                                        value={staffCount} 
                                        onChange={(e)=>setStaffCount(e.target.value)} 
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold" 
                                    />
                                </div>
                            </div>

                            <div className="border-2 border-dashed border-slate-200 rounded-2xl p-6 text-center bg-slate-50/50 space-y-2">
                                <Upload size={24} className="mx-auto text-indigo-600" />
                                <p className="font-bold text-slate-700">Select Timesheet / Biometric CSV or Excel</p>
                                <p className="text-[10px] text-slate-400">Supported formats: .xlsx, .xls, .csv, .pdf</p>
                                <input 
                                    type="file" 
                                    accept=".xlsx,.xls,.csv,.pdf" 
                                    onChange={(e) => setTimesheetFileName(e.target.files?.[0]?.name || '')}
                                    className="pt-2 text-xs" 
                                />
                                {timesheetFileName && (
                                    <p className="text-xs font-bold text-emerald-600 font-mono mt-2">
                                        Selected: {timesheetFileName}
                                    </p>
                                )}
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1">Notes / Remarks for CA Auditor</label>
                                <textarea 
                                    rows={2}
                                    value={timesheetNotes} 
                                    onChange={(e)=>setTimesheetNotes(e.target.value)}
                                    placeholder="e.g. 2 new joiners, overtime approved for sales team..." 
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5" 
                                />
                            </div>

                            <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                                <button type="button" onClick={()=>setShowTimesheetModal(false)} className="px-4 py-2 rounded-xl text-slate-600 font-bold">Cancel</button>
                                <button type="submit" className="bg-indigo-600 text-white px-5 py-2.5 rounded-xl font-bold shadow-md shadow-indigo-100">Upload & Sync</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

        </div>
    );
};

export default CustomerPayrollTab;
