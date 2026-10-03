import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Eye, Download, Printer, FileText, Clock, CheckCircle2, XCircle, AlertCircle, Search, CreditCard } from 'lucide-react';
import GSTInvoiceTemplate from '../admin/finance/GSTInvoiceTemplate';
import { launchRazorpayCheckout } from '../../utils/razorpayCheckout';

const CustomerFinanceView = ({ token, userInfo }) => {
    const [records, setRecords] = useState([]);
    const [loading, setLoading] = useState(false);
    const [selectedRecord, setSelectedRecord] = useState(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [payingId, setPayingId] = useState(null);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchRecords = async () => {
        setLoading(true);
        try {
            // Concurrently fetch orders, payments, and finance records
            const [ordersRes, paymentsRes, financeRes] = await Promise.allSettled([
                axios.get('/api/orders', config),
                axios.get('/api/payments', config),
                axios.get('/api/finance', config)
            ]);

            const orders = ordersRes.status === 'fulfilled' && Array.isArray(ordersRes.value.data) ? ordersRes.value.data : [];
            const payments = paymentsRes.status === 'fulfilled' && Array.isArray(paymentsRes.value.data) ? paymentsRes.value.data : [];
            const financeDocs = financeRes.status === 'fulfilled' && Array.isArray(financeRes.value.data) ? financeRes.value.data : [];

            const unifiedList = [];
            const processedKeys = new Set();

            // 1. Add all explicit milestone invoices from orders (e.g. INV-0310260001)
            orders.forEach(order => {
                const invoices = order.invoices || [];
                invoices.forEach(inv => {
                    const invNumber = inv.number || `INV-${(inv._id || inv.id || 'INV').slice(-6).toUpperCase()}`;
                    const key = invNumber.toUpperCase();
                    if (!processedKeys.has(key)) {
                        processedKeys.add(key);

                        const valAmount = Number(inv.amount || 0);
                        const valSub = Math.round(valAmount / 1.18);
                        const valTax = valAmount - valSub;
                        const valCgst = Math.round(valTax / 2);
                        const valSgst = valTax - valCgst;

                        const isPaid = inv.status === 'Paid' || inv.status === 'Completed';
                        const canPay = !isPaid && inv.status !== 'Cancelled' && inv.status !== 'Draft';

                        unifiedList.push({
                            _id: inv._id || inv.id || `inv_${order._id}_${invNumber}`,
                            orderId: order._id,
                            type: 'TAX INVOICE',
                            number: invNumber,
                            date: inv.createdAt || inv.date || order.createdAt || new Date().toISOString(),
                            dueDate: inv.dueDate,
                            serviceName: order.serviceName,
                            client: {
                                name: order.customerName || order.user?.name || userInfo?.name || 'Valued Client',
                                email: order.customerEmail || order.user?.email || userInfo?.email || '',
                                phone: order.customerPhone || order.user?.phone || userInfo?.phone || '',
                                address: order.companyDetails?.address || 'Registered Office / Business Premises',
                                gstin: order.companyDetails?.gstin || 'URP / N/A'
                            },
                            items: [
                                {
                                    description: inv.description || `${order.serviceName} - Milestone Compliance Invoice`,
                                    hsn: '998311',
                                    qty: 1,
                                    rate: valSub,
                                    taxRate: 18,
                                    amount: valSub
                                }
                            ],
                            totals: {
                                subtotal: valSub,
                                cgst: valCgst,
                                sgst: valSgst,
                                total: valAmount
                            },
                            status: inv.status,
                            isPaid,
                            canPayNow: canPay,
                            url: inv.url || inv.fileUrl || ''
                        });
                    }
                });
            });

            // 2. Add orders that have an unpaid balance and NO separate milestone invoices
            orders.forEach(order => {
                const hasMilestones = (order.invoices || []).length > 0;
                if (!hasMilestones) {
                    const orderPayments = payments.filter(p => (p.order?._id || p.order) === order._id || (p.paymentId && p.paymentId === order.paymentId));
                    const paidForOrder = orderPayments.filter(p => p.status === 'Completed' || p.status === 'Paid').reduce((sum, p) => sum + Number(p.amount || 0), 0);
                    const isOrderPaid = order.paymentStatus === 'Paid' || (order.paymentId && paidForOrder >= Number(order.price || 0));
                    const balance = isOrderPaid ? 0 : Math.max(0, Number(order.price || 0) - paidForOrder);
                    const invNumber = `INV-${order._id.slice(-8).toUpperCase()}`;

                    if (!isOrderPaid && balance > 0 && !processedKeys.has(invNumber.toUpperCase())) {
                        processedKeys.add(invNumber.toUpperCase());

                        const valAmount = balance;
                        const valSub = Math.round(valAmount / 1.18);
                        const valTax = valAmount - valSub;
                        const valCgst = Math.round(valTax / 2);
                        const valSgst = valTax - valCgst;

                        unifiedList.push({
                            _id: order._id,
                            orderId: order._id,
                            type: 'PROFORMA / TAX INVOICE',
                            number: invNumber,
                            date: order.createdAt || new Date().toISOString(),
                            serviceName: order.serviceName,
                            client: {
                                name: order.customerName || order.user?.name || userInfo?.name || 'Valued Client',
                                email: order.customerEmail || order.user?.email || userInfo?.email || '',
                                phone: order.customerPhone || order.user?.phone || userInfo?.phone || '',
                                address: order.companyDetails?.address || 'Registered Office / Business Premises',
                                gstin: order.companyDetails?.gstin || 'URP / N/A'
                            },
                            items: [
                                {
                                    description: `${order.serviceName} (${order.packageName || 'Standard Package'})`,
                                    hsn: '998311',
                                    qty: 1,
                                    rate: valSub,
                                    taxRate: 18,
                                    amount: valSub
                                }
                            ],
                            totals: {
                                subtotal: valSub,
                                cgst: valCgst,
                                sgst: valSgst,
                                total: valAmount
                            },
                            status: paidForOrder > 0 ? 'Partially Paid' : 'Pending',
                            isPaid: false,
                            canPayNow: true,
                            url: ''
                        });
                    }
                }
            });

            // 3. Add all recorded payments (Paid / Completed receipts)
            payments.forEach(p => {
                const invNumber = `INV-${(p.paymentId || p._id || p.id || 'PAY').slice(-8).toUpperCase()}`;
                const key = invNumber.toUpperCase();
                if (!processedKeys.has(key)) {
                    processedKeys.add(key);

                    const valAmount = Number(p.amount || 0);
                    const valSub = Math.round(valAmount / 1.18);
                    const valTax = valAmount - valSub;
                    const valCgst = Math.round(valTax / 2);
                    const valSgst = valTax - valCgst;
                    const isPaid = p.status === 'Completed' || p.status === 'Paid';

                    unifiedList.push({
                        _id: p._id || p.id,
                        orderId: p.order?._id || p.order || '',
                        type: 'TAX INVOICE',
                        number: invNumber,
                        date: p.createdAt || new Date().toISOString(),
                        serviceName: p.serviceName || p.order?.serviceName || 'Professional Compliance & Legal Services',
                        client: {
                            name: p.customerName || userInfo?.name || 'Valued Client',
                            email: p.email || userInfo?.email || '',
                            phone: p.phone || userInfo?.phone || '',
                            address: 'Registered Office / Business Premises',
                            gstin: 'URP / N/A'
                        },
                        items: [
                            {
                                description: p.serviceName || 'Professional Compliance & Legal Services',
                                hsn: '998311',
                                qty: 1,
                                rate: valSub,
                                taxRate: 18,
                                amount: valSub
                            }
                        ],
                        totals: {
                            subtotal: valSub,
                            cgst: valCgst,
                            sgst: valSgst,
                            total: valAmount
                        },
                        status: isPaid ? 'Paid' : p.status,
                        isPaid,
                        canPayNow: !isPaid && p.status !== 'Cancelled',
                        url: p.invoiceUrl || ''
                    });
                }
            });

            // 4. Add any standalone custom finance records from /api/finance
            financeDocs.forEach(f => {
                const invNumber = f.number || `INV-${(f._id || 'FIN').slice(-8).toUpperCase()}`;
                if (!processedKeys.has(invNumber.toUpperCase())) {
                    processedKeys.add(invNumber.toUpperCase());
                    unifiedList.push(f);
                }
            });

            // Sort newest first
            unifiedList.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
            setRecords(unifiedList);
        } catch (error) {
            console.error('Failed to aggregate invoices:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRecords();
    }, [token]);

    const handlePayNow = async (record) => {
        try {
            setPayingId(record._id);
            await launchRazorpayCheckout({
                amount: record.totals?.total || record.amount,
                serviceName: record.serviceName || 'Compliance Invoice Settlement',
                packageName: record.number,
                orderId: record.orderId || record._id,
                customerName: record.client?.name || userInfo?.name,
                customerEmail: record.client?.email || userInfo?.email,
                customerPhone: record.client?.phone || userInfo?.phone,
                onSuccess: async () => {
                    fetchRecords();
                },
                onFailure: (err) => {
                    console.error('Invoice payment failed:', err);
                }
            });
        } catch (err) {
            console.error('Error initiating checkout:', err);
        } finally {
            setPayingId(null);
        }
    };

    const getStatusStyle = (status) => {
        const st = (status || '').toLowerCase();
        if (st === 'paid' || st === 'completed') {
            return { bg: 'bg-emerald-50 text-emerald-700 border-emerald-200', icon: CheckCircle2, label: 'PAID' };
        }
        if (st === 'sent' || st === 'pending' || st === 'unpaid') {
            return { bg: 'bg-amber-50 text-amber-700 border-amber-200', icon: Clock, label: status.toUpperCase() };
        }
        if (st === 'partially paid' || st === 'partial') {
            return { bg: 'bg-orange-50 text-orange-700 border-orange-200', icon: Clock, label: 'PARTIALLY PAID' };
        }
        if (st === 'overdue') {
            return { bg: 'bg-rose-50 text-rose-700 border-rose-200', icon: AlertCircle, label: 'OVERDUE' };
        }
        if (st === 'cancelled') {
            return { bg: 'bg-slate-100 text-slate-600 border-slate-200', icon: XCircle, label: 'CANCELLED' };
        }
        return { bg: 'bg-slate-50 text-slate-700 border-slate-200', icon: Clock, label: (status || 'SENT').toUpperCase() };
    };

    const filteredRecords = records.filter(r => {
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (r.number || '').toLowerCase().includes(q) ||
               (r.serviceName || '').toLowerCase().includes(q) ||
               (r.status || '').toLowerCase().includes(q);
    });

    if (selectedRecord) {
        return (
            <div className="space-y-6 animate-in fade-in zoom-in-95 duration-500 pb-20">
                <div className="flex justify-between items-center bg-white p-4 rounded-2xl border border-slate-100 sticky top-0 z-10 shadow-sm">
                    <button onClick={() => setSelectedRecord(null)} className="flex items-center gap-2 text-slate-600 font-bold text-sm hover:text-slate-900 transition">
                         Back to Billing
                    </button>
                    <div className="flex gap-2">
                        <button onClick={() => window.print()} className="bg-slate-900 text-white px-6 py-2.5 rounded-xl font-bold text-sm hover:bg-slate-800 transition flex items-center gap-2 shadow-lg shadow-slate-200">
                            <Printer size={18} /> Print / Save PDF
                        </button>
                    </div>
                </div>
                <GSTInvoiceTemplate data={selectedRecord} />
            </div>
        );
    }

    return (
        <div className="space-y-6 pb-20">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-2xl font-black text-slate-900 tracking-tight leading-none mb-1">Billing & Invoices</h2>
                    <p className="text-xs text-slate-500 font-medium">View and download your service estimates, proforma, milestone, and GST tax invoices.</p>
                </div>
                <div className="flex items-center gap-3">
                    <div className="relative">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                        <input
                            type="text"
                            placeholder="Search invoices..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="pl-8 pr-3 py-1.5 bg-white border border-slate-200 rounded-xl text-xs font-medium text-slate-900 focus:outline-none focus:ring-2 focus:ring-red-500/20"
                        />
                    </div>
                    <div className="bg-white px-3 py-1.5 rounded-xl border border-slate-100 flex items-center gap-2 text-[10px] font-black text-slate-500 uppercase tracking-widest">
                        <CheckCircle2 size={12} className="text-emerald-500" /> GST Compliant Billing
                    </div>
                </div>
            </div>

            {loading ? (
                <div className="flex flex-col items-center justify-center py-16 bg-white rounded-3xl border border-slate-100 shadow-sm">
                    <div className="w-10 h-10 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-3"></div>
                    <p className="text-slate-400 font-bold text-xs uppercase tracking-widest">Loading Invoices & Receipts...</p>
                </div>
            ) : filteredRecords.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 bg-white rounded-3xl border border-dashed border-slate-200">
                    <div className="w-14 h-14 bg-slate-50 text-slate-300 rounded-2xl flex items-center justify-center mb-3">
                        <FileText size={28} />
                    </div>
                    <p className="text-slate-900 font-black text-base">No Billing History Found</p>
                    <p className="text-slate-400 text-xs font-medium mt-1">Your tax invoices and receipts will appear here once orders are initiated.</p>
                </div>
            ) : (
                <div className="bg-white rounded-3xl border border-slate-200/80 overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/80 text-slate-500 border-b border-slate-200/60">
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Type</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Invoice #</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Service Description</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Date</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Amount</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Status</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filteredRecords.map((record) => {
                                    const style = getStatusStyle(record.status);
                                    const Icon = style.icon;
                                    const amount = record.totals?.total || record.amount || 0;
                                    return (
                                        <tr 
                                            key={record._id} 
                                            onClick={() => setSelectedRecord(record)}
                                            className="hover:bg-slate-50/80 transition-all group cursor-pointer"
                                        >
                                            <td className="px-6 py-4">
                                                <span className="text-[10px] font-black text-indigo-700 bg-indigo-50 border border-indigo-100 px-2.5 py-1 rounded-md uppercase tracking-wider">
                                                    {record.type || 'TAX INVOICE'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <p className="text-xs font-black text-slate-900">#{record.number}</p>
                                            </td>
                                            <td className="px-6 py-4">
                                                <p className="text-xs font-bold text-slate-800 line-clamp-1">{record.serviceName || record.items?.[0]?.description || 'Compliance Service'}</p>
                                            </td>
                                            <td className="px-6 py-4 text-center">
                                                <p className="text-xs font-bold text-slate-600">{new Date(record.date).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
                                            </td>
                                            <td className="px-6 py-4 text-center">
                                                <p className="text-xs font-black text-slate-900 tracking-tight">₹{amount.toLocaleString()}</p>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex justify-center">
                                                    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border ${style.bg}`}>
                                                        <Icon size={12} /> {style.label}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-right" onClick={e => e.stopPropagation()}>
                                                <div className="flex items-center justify-end gap-2">
                                                    {record.canPayNow && (
                                                        <button 
                                                            onClick={() => handlePayNow(record)}
                                                            disabled={payingId === record._id}
                                                            className="px-3.5 py-1.5 bg-red-600 text-white font-black text-[10px] rounded-xl uppercase tracking-wider hover:bg-red-700 transition shadow-sm flex items-center gap-1.5 disabled:opacity-50"
                                                        >
                                                            <CreditCard size={12} /> {payingId === record._id ? 'Opening...' : `Pay ₹${amount.toLocaleString()}`}
                                                        </button>
                                                    )}
                                                    <button 
                                                        onClick={() => setSelectedRecord(record)}
                                                        className="p-2 bg-slate-100 text-slate-600 group-hover:text-red-600 group-hover:bg-red-50 rounded-xl transition-all flex items-center gap-1 text-[11px] font-bold"
                                                        title="View Tax Invoice PDF"
                                                    >
                                                        <Eye size={15} /> View Invoice
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CustomerFinanceView;
