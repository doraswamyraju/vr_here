import React from 'react';
import { BarChart3, TrendingUp, TrendingDown, DollarSign, PieChart, ShieldCheck, Download } from 'lucide-react';

const ReportsTab = ({ transactions = [], company }) => {
    // Computations
    const salesTxs = transactions.filter(t => t.transactionType === 'Sales');
    const purchaseTxs = transactions.filter(t => t.transactionType === 'Purchase');
    const incomeTxs = transactions.filter(t => t.transactionType === 'Income');
    const expenseTxs = transactions.filter(t => t.transactionType === 'Expense');

    const totalSales = salesTxs.reduce((acc, c) => acc + (c.summary?.totalTaxableValue || 0), 0);
    const totalPurchases = purchaseTxs.reduce((acc, c) => acc + (c.summary?.totalTaxableValue || 0), 0);
    const grossProfit = totalSales - totalPurchases;

    const otherIncome = incomeTxs.reduce((acc, c) => acc + (c.summary?.totalAmount || 0), 0);
    const operationalExpenses = expenseTxs.reduce((acc, c) => acc + (c.summary?.totalAmount || 0), 0);
    const netProfit = grossProfit + otherIncome - operationalExpenses;

    const outputGst = salesTxs.reduce((acc, c) => acc + ((c.summary?.totalCgst || 0) + (c.summary?.totalSgst || 0) + (c.summary?.totalIgst || 0)), 0);
    const inputGst = purchaseTxs
        .filter(t => t.itcEligibility !== 'Ineligible')
        .reduce((acc, c) => acc + ((c.summary?.totalCgst || 0) + (c.summary?.totalSgst || 0) + (c.summary?.totalIgst || 0)), 0);
    const netGstPayable = Math.max(0, outputGst - inputGst);

    return (
        <div className="space-y-6">
            {/* Top Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm">
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Gross Sales Revenue</p>
                    <h3 className="text-2xl font-black text-slate-900 mt-1">₹{totalSales.toLocaleString('en-IN')}</h3>
                    <p className="text-[11px] text-emerald-600 font-bold mt-0.5">Taxable Outward Supplies</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm">
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Cost of Goods (COGS)</p>
                    <h3 className="text-2xl font-black text-slate-900 mt-1">₹{totalPurchases.toLocaleString('en-IN')}</h3>
                    <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Inward Taxable Purchases</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm">
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Net Business Profit</p>
                    <h3 className={`text-2xl font-black mt-1 ${netProfit >= 0 ? 'text-emerald-600' : 'text-rose-600'}`}>
                        ₹{netProfit.toLocaleString('en-IN')}
                    </h3>
                    <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Before Income Tax</p>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm">
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Net GST Payable (Cash)</p>
                    <h3 className="text-2xl font-black text-indigo-950 mt-1">₹{netGstPayable.toLocaleString('en-IN')}</h3>
                    <p className="text-[11px] text-indigo-600 font-bold mt-0.5">Output GST minus Input ITC</p>
                </div>
            </div>

            {/* Profit & Loss Statement Summary */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 p-6 space-y-6">
                <div className="flex justify-between items-center border-b border-slate-100 pb-4">
                    <div>
                        <h3 className="font-black text-slate-900 text-lg">Profit & Loss Statement (P&L Summary)</h3>
                        <p className="text-xs text-slate-500 font-medium">Auto-aggregated from your verified sales, purchases, and expense vouchers</p>
                    </div>
                    <button 
                        onClick={() => window.print()}
                        className="bg-slate-100 hover:bg-slate-200 text-slate-800 px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5"
                    >
                        <Download size={14} /> Export Report
                    </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 text-xs">
                    {/* Income Side */}
                    <div className="space-y-4">
                        <h4 className="font-black text-emerald-800 uppercase tracking-wider text-xs border-b border-emerald-100 pb-2">
                            Revenue & Income
                        </h4>
                        <div className="space-y-2">
                            <div className="flex justify-between py-1.5 border-b border-slate-50">
                                <span className="font-bold text-slate-700">Sales Invoices Revenue:</span>
                                <span className="font-mono font-bold text-slate-900">₹{totalSales.toLocaleString('en-IN')}</span>
                            </div>
                            <div className="flex justify-between py-1.5 border-b border-slate-50">
                                <span className="font-bold text-slate-700">Other Business Income / Receipts:</span>
                                <span className="font-mono font-bold text-slate-900">₹{otherIncome.toLocaleString('en-IN')}</span>
                            </div>
                            <div className="flex justify-between py-2 border-t-2 border-slate-800 font-black text-slate-900 text-sm">
                                <span>Total Revenue:</span>
                                <span className="font-mono text-emerald-600">₹{(totalSales + otherIncome).toLocaleString('en-IN')}</span>
                            </div>
                        </div>
                    </div>

                    {/* Expense Side */}
                    <div className="space-y-4">
                        <h4 className="font-black text-rose-800 uppercase tracking-wider text-xs border-b border-rose-100 pb-2">
                            Cost & Expenses
                        </h4>
                        <div className="space-y-2">
                            <div className="flex justify-between py-1.5 border-b border-slate-50">
                                <span className="font-bold text-slate-700">Direct Purchases (COGS):</span>
                                <span className="font-mono font-bold text-slate-900">₹{totalPurchases.toLocaleString('en-IN')}</span>
                            </div>
                            <div className="flex justify-between py-1.5 border-b border-slate-50">
                                <span className="font-bold text-slate-700">Operating & Administrative Expenses:</span>
                                <span className="font-mono font-bold text-slate-900">₹{operationalExpenses.toLocaleString('en-IN')}</span>
                            </div>
                            <div className="flex justify-between py-2 border-t-2 border-slate-800 font-black text-slate-900 text-sm">
                                <span>Total Costs & Expenses:</span>
                                <span className="font-mono text-rose-600">₹{(totalPurchases + operationalExpenses).toLocaleString('en-IN')}</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Net Balance Highlight */}
                <div className="bg-slate-900 text-white p-5 rounded-2xl flex flex-col sm:flex-row justify-between items-center gap-4">
                    <div>
                        <span className="text-[10px] font-bold text-indigo-300 uppercase tracking-widest">Bottom Line Result</span>
                        <h3 className="text-xl font-black mt-0.5">Estimated Net Profit for Period</h3>
                    </div>
                    <div className="font-mono font-black text-3xl text-emerald-400">
                        ₹{netProfit.toLocaleString('en-IN')}.00
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReportsTab;
