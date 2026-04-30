import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Plus, Trash2, Save, Calculator, User, Building2, MapPin, Hash, Calendar } from 'lucide-react';

const FinanceForm = ({ type, initialData, token, onSuccess }) => {
    const [formData, setFormData] = useState({
        type: type,
        number: '',
        date: new Date().toISOString().split('T')[0],
        dueDate: '',
        client: {
            user: null,
            name: '',
            address: '',
            gstin: '',
            phone: '',
            email: ''
        },
        items: [{ description: '', hsn: '', qty: 1, rate: 0, taxRate: 18, amount: 0 }],
        totals: { subtotal: 0, cgst: 0, sgst: 0, igst: 0, total: 0 },
        status: 'Draft',
        notes: '',
        terms: ''
    });

    const [isSubmitting, setIsSubmitting] = useState(false);

    useEffect(() => {
        if (initialData) {
            setFormData({
                ...initialData,
                date: new Date(initialData.date).toISOString().split('T')[0],
                dueDate: initialData.dueDate ? new Date(initialData.dueDate).toISOString().split('T')[0] : ''
            });
        } else {
            // Auto-generate number based on type
            const prefix = type.substring(0, 3).toUpperCase();
            const random = Math.floor(1000 + Math.random() * 9000);
            setFormData(prev => ({ ...prev, number: `${prefix}-${random}`, type }));
        }
    }, [initialData, type]);

    const calculateTotals = (items) => {
        let subtotal = 0;
        let cgst = 0;
        let sgst = 0;
        let igst = 0;

        const updatedItems = items.map(item => {
            const amount = item.qty * item.rate;
            const tax = (amount * item.taxRate) / 100;
            
            // Simplified: Assuming CGST/SGST for now. 
            // In a real app, this depends on Place of Supply vs Business Location
            const itemCgst = tax / 2;
            const itemSgst = tax / 2;
            
            subtotal += amount;
            cgst += itemCgst;
            sgst += itemSgst;

            return { ...item, amount, cgst: itemCgst, sgst: itemSgst };
        });

        const total = subtotal + cgst + sgst + igst;

        return {
            items: updatedItems,
            totals: { subtotal, cgst, sgst, igst, total }
        };
    };

    const handleItemChange = (index, field, value) => {
        const newItems = [...formData.items];
        newItems[index][field] = field === 'description' || field === 'hsn' ? value : Number(value);
        
        const { items, totals } = calculateTotals(newItems);
        setFormData(prev => ({ ...prev, items, totals }));
    };

    const addItem = () => {
        setFormData(prev => ({
            ...prev,
            items: [...prev.items, { description: '', hsn: '', qty: 1, rate: 0, taxRate: 18, amount: 0 }]
        }));
    };

    const removeItem = (index) => {
        if (formData.items.length === 1) return;
        const newItems = formData.items.filter((_, i) => i !== index);
        const { items, totals } = calculateTotals(newItems);
        setFormData(prev => ({ ...prev, items, totals }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            const config = { headers: { Authorization: `Bearer ${token}` } };
            if (initialData) {
                await axios.put(`/api/finance/${initialData._id}`, formData, config);
            } else {
                await axios.post('/api/finance', formData, config);
            }
            onSuccess();
        } catch (error) {
            alert(error?.response?.data?.message || 'Failed to save record');
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-8 pb-20">
            {/* Header Info */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white p-6 rounded-3xl border border-slate-100 space-y-4">
                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                        <Hash size={12} /> Document Info
                    </p>
                    <div className="space-y-3">
                        <div>
                            <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Document #</label>
                            <input 
                                type="text" 
                                className="w-full px-4 py-2.5 bg-slate-50 border-none rounded-xl text-sm font-black focus:ring-2 focus:ring-red-500/20"
                                value={formData.number}
                                onChange={(e) => setFormData(prev => ({ ...prev, number: e.target.value }))}
                                required
                            />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                            <div>
                                <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Date</label>
                                <input 
                                    type="date" 
                                    className="w-full px-4 py-2.5 bg-slate-50 border-none rounded-xl text-sm font-bold focus:ring-2 focus:ring-red-500/20"
                                    value={formData.date}
                                    onChange={(e) => setFormData(prev => ({ ...prev, date: e.target.value }))}
                                    required
                                />
                            </div>
                            <div>
                                <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Due Date</label>
                                <input 
                                    type="date" 
                                    className="w-full px-4 py-2.5 bg-slate-50 border-none rounded-xl text-sm font-bold focus:ring-2 focus:ring-red-500/20"
                                    value={formData.dueDate}
                                    onChange={(e) => setFormData(prev => ({ ...prev, dueDate: e.target.value }))}
                                />
                            </div>
                        </div>
                    </div>
                </div>

                <div className="md:col-span-2 bg-white p-6 rounded-3xl border border-slate-100 space-y-4">
                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                        <User size={12} /> Client Details
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="space-y-3">
                            <input 
                                type="text" 
                                placeholder="Client Name"
                                className="w-full px-4 py-2.5 bg-slate-50 border-none rounded-xl text-sm font-bold focus:ring-2 focus:ring-red-500/20"
                                value={formData.client.name}
                                onChange={(e) => setFormData(prev => ({ ...prev, client: { ...prev.client, name: e.target.value } }))}
                                required
                            />
                            <input 
                                type="text" 
                                placeholder="Client GSTIN (Optional)"
                                className="w-full px-4 py-2.5 bg-slate-50 border-none rounded-xl text-sm font-bold focus:ring-2 focus:ring-red-500/20"
                                value={formData.client.gstin}
                                onChange={(e) => setFormData(prev => ({ ...prev, client: { ...prev.client, gstin: e.target.value } }))}
                            />
                        </div>
                        <div className="space-y-3">
                            <textarea 
                                placeholder="Client Address"
                                className="w-full px-4 py-2.5 bg-slate-50 border-none rounded-xl text-sm font-bold focus:ring-2 focus:ring-red-500/20 h-[88px] resize-none"
                                value={formData.client.address}
                                onChange={(e) => setFormData(prev => ({ ...prev, client: { ...prev.client, address: e.target.value } }))}
                            />
                        </div>
                    </div>
                </div>
            </div>

            {/* Items Table */}
            <div className="bg-white rounded-3xl border border-slate-100 overflow-hidden shadow-xl shadow-slate-200/50">
                <table className="w-full text-left">
                    <thead>
                        <tr className="bg-slate-50/50 text-slate-400">
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Description</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center w-32">HSN</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center w-24">Qty</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center w-32">Rate</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center w-24">GST %</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-right w-32">Amount</th>
                            <th className="px-6 py-4 text-right w-16"></th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                        {formData.items.map((item, index) => (
                            <tr key={index}>
                                <td className="px-6 py-4">
                                    <input 
                                        type="text" 
                                        className="w-full px-3 py-2 bg-slate-50 border-none rounded-lg text-sm font-bold focus:ring-2 focus:ring-red-500/10"
                                        value={item.description}
                                        onChange={(e) => handleItemChange(index, 'description', e.target.value)}
                                        placeholder="Item description..."
                                        required
                                    />
                                </td>
                                <td className="px-6 py-4">
                                    <input 
                                        type="text" 
                                        className="w-full px-3 py-2 bg-slate-50 border-none rounded-lg text-sm font-bold text-center focus:ring-2 focus:ring-red-500/10"
                                        value={item.hsn}
                                        onChange={(e) => handleItemChange(index, 'hsn', e.target.value)}
                                        placeholder="HSN"
                                    />
                                </td>
                                <td className="px-6 py-4">
                                    <input 
                                        type="number" 
                                        className="w-full px-3 py-2 bg-slate-50 border-none rounded-lg text-sm font-black text-center focus:ring-2 focus:ring-red-500/10"
                                        value={item.qty}
                                        onChange={(e) => handleItemChange(index, 'qty', e.target.value)}
                                        min="1"
                                    />
                                </td>
                                <td className="px-6 py-4">
                                    <input 
                                        type="number" 
                                        className="w-full px-3 py-2 bg-slate-50 border-none rounded-lg text-sm font-black text-center focus:ring-2 focus:ring-red-500/10"
                                        value={item.rate}
                                        onChange={(e) => handleItemChange(index, 'rate', e.target.value)}
                                    />
                                </td>
                                <td className="px-6 py-4">
                                    <select 
                                        className="w-full px-3 py-2 bg-slate-50 border-none rounded-lg text-xs font-black text-center focus:ring-2 focus:ring-red-500/10"
                                        value={item.taxRate}
                                        onChange={(e) => handleItemChange(index, 'taxRate', e.target.value)}
                                    >
                                        <option value="0">0%</option>
                                        <option value="5">5%</option>
                                        <option value="12">12%</option>
                                        <option value="18">18%</option>
                                        <option value="28">28%</option>
                                    </select>
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <span className="text-sm font-black text-slate-900">₹{item.amount.toLocaleString()}</span>
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <button 
                                        type="button" 
                                        onClick={() => removeItem(index)}
                                        className="p-1.5 text-slate-300 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                <div className="p-4 bg-slate-50/50">
                    <button 
                        type="button" 
                        onClick={addItem}
                        className="flex items-center gap-2 text-xs font-black text-red-600 uppercase tracking-widest hover:text-red-700 transition"
                    >
                        <Plus size={14} /> Add Row
                    </button>
                </div>
            </div>

            {/* Totals and Notes */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="space-y-4">
                    <div className="bg-white p-6 rounded-3xl border border-slate-100">
                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2 block">Notes & Terms</label>
                        <textarea 
                            className="w-full px-4 py-3 bg-slate-50 border-none rounded-2xl text-sm font-medium focus:ring-2 focus:ring-red-500/20 h-32 resize-none"
                            placeholder="Add internal notes or terms and conditions..."
                            value={formData.notes}
                            onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))}
                        />
                    </div>
                </div>
                <div className="space-y-4">
                    <div className="bg-slate-900 text-white p-8 rounded-3xl shadow-2xl shadow-slate-300">
                        <div className="space-y-4">
                            <div className="flex justify-between items-center text-sm">
                                <span className="font-bold text-slate-400">Subtotal</span>
                                <span className="font-black">₹{formData.totals.subtotal.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between items-center text-xs">
                                <span className="font-bold text-slate-500 uppercase tracking-widest">Tax (GST)</span>
                                <span className="font-black">₹{(formData.totals.cgst + formData.totals.sgst + formData.totals.igst).toLocaleString()}</span>
                            </div>
                            <div className="pt-4 border-t border-white/10 flex justify-between items-center">
                                <span className="text-xl font-black tracking-tighter uppercase">Grand Total</span>
                                <span className="text-3xl font-black tracking-tighter text-red-500">₹{formData.totals.total.toLocaleString()}</span>
                            </div>
                        </div>
                        <button 
                            type="submit" 
                            disabled={isSubmitting}
                            className="w-full mt-8 bg-red-600 hover:bg-red-700 text-white font-black py-4 rounded-2xl shadow-xl shadow-red-900/20 transition transform active:scale-[0.98] flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                            {isSubmitting ? <Calculator className="animate-spin" /> : <Save size={20} />}
                            {initialData ? 'Update' : 'Generate'} {type}
                        </button>
                    </div>
                </div>
            </div>
        </form>
    );
};

export default FinanceForm;
