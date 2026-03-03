import React, { useState, useEffect } from 'react';
import {
    MessageCircle, Plus, Send, ChevronRight,
    Headphones, Clock, CheckCircle2, AlertCircle,
    Mail, Phone, MessageSquare
} from 'lucide-react';
import axios from 'axios';

const SupportView = ({ userInfo }) => {
    const [tickets, setTickets] = useState([]);
    const [showCreate, setShowCreate] = useState(false);
    const [subject, setSubject] = useState('');
    const [description, setDescription] = useState('');
    const [priority, setPriority] = useState('Low');
    const [loading, setLoading] = useState(false);

    const fetchTickets = async () => {
        try {
            const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
            const { data } = await axios.get('/api/tickets', config);
            setTickets(data);
        } catch (error) {
            console.error(error);
        }
    };

    useEffect(() => {
        fetchTickets();
    }, []);

    const handleCreateTicket = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
            await axios.post('/api/tickets', { subject, description, priority }, config);
            alert('Ticket created successfully!');
            setShowCreate(false);
            setSubject('');
            setDescription('');
            fetchTickets();
        } catch (error) {
            console.error(error);
            alert('Error creating ticket');
        }
        setLoading(false);
    };

    const StatusBadge = ({ status }) => {
        const styles = {
            'Open': 'bg-emerald-100 text-emerald-700 border-emerald-200',
            'In Progress': 'bg-blue-100 text-blue-700 border-blue-200',
            'Closed': 'bg-slate-100 text-slate-500 border-slate-200',
        };
        return <span className={`px-2 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-wider border ${styles[status]}`}>{status}</span>;
    };

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Support</h1>
                    <p className="text-slate-500 text-sm">Need help? We're here for you.</p>
                </div>
                {!showCreate && (
                    <button
                        onClick={() => setShowCreate(true)}
                        className="bg-indigo-600 text-white p-3 rounded-2xl shadow-lg shadow-indigo-100 transform active:scale-95 transition-all"
                    >
                        <Plus size={20} />
                    </button>
                )}
            </div>

            {showCreate ? (
                <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm space-y-4 animate-in zoom-in-95 duration-300">
                    <div className="flex justify-between items-center mb-2">
                        <h3 className="font-black text-slate-800">Raise a Ticket</h3>
                        <button onClick={() => setShowCreate(false)} className="text-slate-400 font-bold text-xs uppercase tracking-widest px-3 py-1 bg-slate-50 rounded-lg">Cancel</button>
                    </div>
                    <form onSubmit={handleCreateTicket} className="space-y-4">
                        <div className="space-y-1.5 px-1">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Subject</label>
                            <input
                                required
                                type="text"
                                value={subject}
                                onChange={e => setSubject(e.target.value)}
                                placeholder="Issue with my order #..."
                                className="w-full px-4 py-3.5 bg-slate-50 border-none rounded-2xl outline-none font-bold text-slate-800 text-sm focus:ring-2 focus:ring-indigo-500/10 transition-all shadow-inner"
                            />
                        </div>
                        <div className="space-y-1.5 px-1">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Priority</label>
                            <select
                                value={priority}
                                onChange={e => setPriority(e.target.value)}
                                className="w-full px-4 py-3.5 bg-slate-50 border-none rounded-2xl outline-none font-bold text-slate-800 text-sm focus:ring-2 focus:ring-indigo-500/10 transition-all appearance-none shadow-inner"
                            >
                                <option value="Low">Low</option>
                                <option value="Medium">Medium</option>
                                <option value="High">High</option>
                            </select>
                        </div>
                        <div className="space-y-1.5 px-1">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Description</label>
                            <textarea
                                required
                                rows="4"
                                value={description}
                                onChange={e => setDescription(e.target.value)}
                                placeholder="Describe your issue in detail..."
                                className="w-full px-4 py-3.5 bg-slate-50 border-none rounded-2xl outline-none font-bold text-slate-800 text-sm focus:ring-2 focus:ring-indigo-500/10 transition-all shadow-inner resize-none"
                            ></textarea>
                        </div>
                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-indigo-600 text-white py-4 rounded-2xl text-sm font-black shadow-lg shadow-indigo-100 flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50 transition-all"
                        >
                            {loading ? 'Creating...' : <><Send size={18} /> Submit Ticket</>}
                        </button>
                    </form>
                </div>
            ) : (
                <>
                    {/* Quick Contact Options */}
                    <div className="grid grid-cols-2 gap-4">
                        <a href="tel:+918008530606" className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col items-center gap-3 active:scale-95 transition-all text-center group">
                            <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center border border-indigo-100/50 group-hover:bg-indigo-600 group-hover:text-white transition-all">
                                <Phone size={24} />
                            </div>
                            <div>
                                <h4 className="font-black text-slate-800 text-xs">Call Us</h4>
                                <p className="text-[9px] text-slate-400 font-bold uppercase tracking-tighter">Immediate Help</p>
                            </div>
                        </a>
                        <a href="https://wa.me/918008530606" target="_blank" rel="noreferrer" className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col items-center gap-3 active:scale-95 transition-all text-center group font-black">
                            <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-2xl flex items-center justify-center border border-emerald-100/50 group-hover:bg-emerald-600 group-hover:text-white transition-all font-black">
                                <MessageSquare size={24} />
                            </div>
                            <div>
                                <h4 className="font-black text-slate-800 text-xs uppercase tracking-tighter">WhatsApp</h4>
                                <p className="text-[9px] text-slate-400 font-bold uppercase tracking-tighter">Quick Response</p>
                            </div>
                        </a>
                    </div>

                    {/* Tickets Header */}
                    <div>
                        <div className="flex justify-between items-center mb-4 px-1">
                            <h3 className="font-black text-slate-800 text-lg flex items-center gap-2">
                                <MessageCircle size={18} className="text-indigo-600" />
                                Your Tickets
                            </h3>
                            <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{tickets.length} Total</span>
                        </div>

                        {/* Recent Tickets List */}
                        <div className="space-y-4">
                            {tickets.map((ticket) => (
                                <div key={ticket._id} className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm group hover:border-indigo-100 transition-all active:scale-[0.98]">
                                    <div className="flex justify-between items-start mb-3">
                                        <div className="max-w-[70%]">
                                            <h4 className="font-black text-slate-800 text-sm line-clamp-1 group-hover:text-indigo-600 transition-colors uppercase tracking-tight">{ticket.subject}</h4>
                                            <div className="flex items-center gap-1.5 text-[9px] text-slate-400 font-bold uppercase tracking-wider">
                                                <Clock size={10} />
                                                <span>{new Date(ticket.createdAt).toLocaleDateString()}</span>
                                            </div>
                                        </div>
                                        <StatusBadge status={ticket.status} />
                                    </div>
                                    <div className="flex items-center justify-between pt-1">
                                        <div className="flex items-center gap-1 text-[10px] text-slate-500 font-bold uppercase">
                                            Priority: <span className={`${ticket.priority === 'High' ? 'text-rose-500' : ticket.priority === 'Medium' ? 'text-amber-500' : 'text-blue-500'}`}>{ticket.priority}</span>
                                        </div>
                                        <div className="w-8 h-8 rounded-full bg-slate-50 flex items-center justify-center text-slate-300 group-hover:bg-indigo-50 group-hover:text-indigo-500 transition-all font-black">
                                            <ChevronRight size={16} />
                                        </div>
                                    </div>
                                </div>
                            ))}

                            {tickets.length === 0 && (
                                <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-12 text-center text-slate-300">
                                    <Headphones size={32} className="mx-auto mb-2 opacity-30" />
                                    <p className="text-xs font-black uppercase tracking-widest">No active tickets</p>
                                    <p className="text-[10px] text-slate-400 font-medium px-8 mt-1 leading-relaxed">Raise a ticket for any assistance or inquiries about our services.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default SupportView;
