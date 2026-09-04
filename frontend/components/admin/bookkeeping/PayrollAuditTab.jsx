import React, { useState } from 'react';
import { Users, Plus, Download, FileText, CheckCircle2, DollarSign } from 'lucide-react';

const PayrollAuditTab = ({
    payrollRecords = [],
    selectedClient,
    onAddRecord,
    onRefresh
}) => {
    const [showAddModal, setShowAddModal] = useState(false);
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

    const grossSalary = Number(basic) + Number(hra) + Number(allowances);
    const totalDeductions = Number(pf) + Number(pt) + Number(tds);
    const netPayable = grossSalary - totalDeductions;

    const handleSave = (e) => {
        e.preventDefault();
        if (!employeeName || !employeePan) {
            alert('Please enter employee name and PAN');
            return;
        }

        if (onAddRecord) {
            onAddRecord({
                clientId: selectedClient._id,
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
                netPayable
            });
        }
        setShowAddModal(false);
    };

    return (
        <div className="space-y-6">
            <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 space-y-6">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-100 pb-4">
                    <div>
                        <h4 className="font-black text-slate-900 text-lg">Employee Salary & Form 16 / TDS Register</h4>
                        <p className="text-xs text-slate-500 font-medium">Monthly payroll registers, salary slips, and TDS Sec 192/194 compliance</p>
                    </div>

                    <button 
                        onClick={() => setShowAddModal(true)}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider flex items-center gap-1.5 transition shadow-md shadow-indigo-100"
                    >
                        <Plus size={15} /> Add Employee Salary Entry
                    </button>
                </div>

                {payrollRecords.length === 0 ? (
                    <div className="text-center py-20 text-slate-400">
                        <Users size={48} className="mx-auto mb-3 opacity-30" />
                        <p className="font-bold">No payroll records entered for this client</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-5 py-3.5">Month</th>
                                    <th className="px-5 py-3.5">Employee Name</th>
                                    <th className="px-5 py-3.5">PAN</th>
                                    <th className="px-5 py-3.5">Gross (₹)</th>
                                    <th className="px-5 py-3.5">PF / PT (₹)</th>
                                    <th className="px-5 py-3.5">TDS u/s 192 (₹)</th>
                                    <th className="px-5 py-3.5">Net Salary (₹)</th>
                                    <th className="px-5 py-3.5">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {payrollRecords.map(pr => (
                                    <tr key={pr._id} className="hover:bg-slate-50/60">
                                        <td className="px-5 py-3.5 font-bold text-slate-700">{pr.month}</td>
                                        <td className="px-5 py-3.5 font-black text-slate-900">{pr.employeeName}</td>
                                        <td className="px-5 py-3.5 font-mono text-slate-500">{pr.employeePan}</td>
                                        <td className="px-5 py-3.5 font-mono font-bold text-slate-800">₹{pr.grossSalary?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 font-mono text-slate-600">₹{(pr.pfEmployee + pr.professionalTax)?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 font-mono font-bold text-rose-600">₹{pr.tdsDeducted?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5 font-mono font-black text-emerald-600 text-sm">₹{pr.netPayable?.toLocaleString('en-IN')}</td>
                                        <td className="px-5 py-3.5">
                                            <span className="px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider bg-emerald-50 text-emerald-700 border border-emerald-200">
                                                {pr.status || 'Processed'}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-sm">Add Salary Register Row</h3>
                            <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-600">✕</button>
                        </div>

                        <form onSubmit={handleSave} className="p-6 space-y-3.5 text-xs">
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Month / Year *</label>
                                    <input type="text" value={month} onChange={(e)=>setMonth(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-bold" required />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Employee Name *</label>
                                    <input type="text" value={employeeName} onChange={(e)=>setEmployeeName(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-bold" required />
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Employee PAN *</label>
                                    <input type="text" value={employeePan} onChange={(e)=>setEmployeePan(e.target.value.toUpperCase())} maxLength={10} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono uppercase" required />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-1">Designation</label>
                                    <input type="text" value={designation} onChange={(e)=>setDesignation(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2" />
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
        </div>
    );
};

export default PayrollAuditTab;
