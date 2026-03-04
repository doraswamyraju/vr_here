import React from 'react';
import {
    CreditCard, Download, Receipt, CheckCircle2,
    ArrowUpRight, Wallet, History, Search
} from 'lucide-react';

const AccountsView = ({ orders, payments }) => {
    const totalSpent = payments.reduce((acc, curr) => acc + curr.amount, 0);

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Accounts</h1>
                    <p className="text-slate-500 text-sm">Past payment details & invoices.</p>
                </div>
            </div>

            {/* Wallet / Balance Card */}
            <div className="bg-slate-900 rounded-3xl p-6 text-white relative overflow-hidden shadow-xl shadow-slate-200">
                <div className="absolute top-0 right-0 w-48 h-48 bg-emerald-500/10 rounded-full -mr-24 -mt-24 blur-3xl"></div>
                <div className="relative z-10 space-y-6">
                    <div className="flex justify-between items-center">
                        <div className="w-10 h-10 bg-white/10 rounded-2xl flex items-center justify-center">
                            <Wallet className="text-emerald-400" size={20} />
                        </div>
                        <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 bg-white/5 px-2 py-1 rounded-lg">Active Account</span>
                    </div>
                    <div>
                        <p className="text-slate-400 text-[10px] font-black uppercase tracking-widest mb-1">Total Investment</p>
                        <h2 className="text-4xl font-black tracking-tight leading-none">₹{totalSpent.toLocaleString()}</h2>
                    </div>
                    <div className="flex gap-4 pt-2">
                        <div className="flex-1 bg-white/5 p-3 rounded-2xl border border-white/10">
                            <p className="text-slate-500 text-[9px] font-black uppercase mb-1">Total Orders</p>
                            <p className="font-black text-xl">{orders.length}</p>
                        </div>
                        <div className="flex-1 bg-white/5 p-3 rounded-2xl border border-white/10">
                            <p className="text-slate-500 text-[9px] font-black uppercase mb-1">Credits Used</p>
                            <p className="font-black text-xl">₹0</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Transactions Header */}
            <div>
                <div className="flex justify-between items-center mb-4 px-1">
                    <h3 className="font-black text-slate-800 text-lg flex items-center gap-2">
                        <History size={18} className="text-indigo-600" />
                        Transactions
                    </h3>
                    <button className="text-[10px] font-black text-indigo-600 uppercase tracking-wider">Export All</button>
                </div>

                {/* Transactions List */}
                <div className="space-y-3 lg:grid lg:grid-cols-2 lg:gap-4 lg:space-y-0">
                    {payments.map((payment) => (
                        <div key={payment._id} className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between group hover:border-indigo-100 transition-all">
                            <div className="flex items-center gap-4">
                                <div className="w-12 h-12 bg-slate-50 text-indigo-600 rounded-2xl flex items-center justify-center border border-slate-100 group-hover:bg-indigo-50 transition-colors">
                                    <Receipt size={20} />
                                </div>
                                <div className="max-w-[150px] md:max-w-none">
                                    <h4 className="font-black text-slate-800 text-sm line-clamp-1">{payment.order?.serviceName || 'Service Payment'}</h4>
                                    <div className="flex items-center gap-1.5 text-[9px] text-slate-400 font-bold uppercase tracking-wider">
                                        <CheckCircle2 size={10} className={payment.status === 'Completed' ? "text-emerald-500" : "text-amber-500"} />
                                        <span>{payment.status} • {new Date(payment.createdAt).toLocaleDateString()}</span>
                                    </div>
                                </div>
                            </div>
                            <div className="text-right flex flex-col items-end gap-1">
                                <span className="font-black text-slate-800 text-sm">₹{payment.amount.toLocaleString()}</span>
                                <a
                                    href={payment.invoiceUrl || '#'}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="flex items-center gap-1 text-[9px] font-black text-indigo-600 uppercase tracking-widest bg-indigo-50 px-2 py-1 rounded-lg hover:bg-indigo-600 hover:text-white transition-all"
                                >
                                    Invoice <Download size={10} />
                                </a>
                            </div>
                        </div>
                    ))}

                    {payments.length === 0 && (
                        <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-10 text-center text-slate-300">
                            <Receipt size={32} className="mx-auto mb-2 opacity-30" />
                            <p className="text-xs font-bold">No transactions found</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Help / FAQ Mini Card */}
            <div className="bg-indigo-50 rounded-3xl p-6 border border-indigo-100 flex items-start gap-4">
                <div className="w-10 h-10 bg-white rounded-2xl flex items-center justify-center shadow-sm text-indigo-600 shrink-0">
                    <ArrowUpRight size={20} />
                </div>
                <div>
                    <h4 className="text-sm font-black text-indigo-900 mb-1">Billing Questions?</h4>
                    <p className="text-[10px] text-indigo-700/70 mb-3 leading-relaxed">If you have any discrepancy in your invoice or payment status, please reach out to our accounts team directly.</p>
                    <button className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest shadow-lg shadow-indigo-200 hover:bg-indigo-700 transition-all">
                        Open Support Ticket
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AccountsView;
