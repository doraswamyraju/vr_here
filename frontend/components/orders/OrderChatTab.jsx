import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { 
    Send, Paperclip, Lock, MessageSquare, Shield, User, 
    CheckCheck, Clock, Download, FileText, AlertCircle, 
    RefreshCw, Sparkles, X, Check, Image as ImageIcon, File
} from 'lucide-react';

const OrderChatTab = ({ order, userInfo }) => {
    const isStaff = userInfo?.role === 'admin' || userInfo?.role === 'employee' || userInfo?.role === 'freelancer';
    
    // Default mode for staff: 'client' or 'internal' (customers are always 'client')
    const [channelMode, setChannelMode] = useState(isStaff ? 'client' : 'client');
    const [messages, setMessages] = useState([]);
    const [loading, setLoading] = useState(true);
    const [sending, setSending] = useState(false);
    const [inputText, setInputText] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);
    const [errorMsg, setErrorMsg] = useState('');
    const [refreshing, setRefreshing] = useState(false);

    const messagesEndRef = useRef(null);
    const fileInputRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    const fetchMessages = async (showLoading = false) => {
        if (!order?._id) return;
        if (showLoading) setLoading(true);
        try {
            const token = userInfo?.token || localStorage.getItem('token');
            const res = await axios.get(`/api/orders/${order._id}/messages`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setMessages(res.data || []);
            setErrorMsg('');
        } catch (err) {
            console.error('[OrderChat] Failed to load messages:', err);
            setErrorMsg(err.response?.data?.message || 'Failed to load conversation');
        } finally {
            if (showLoading) setLoading(false);
            setRefreshing(false);
        }
    };

    // Initial load + Polling every 7 seconds
    useEffect(() => {
        fetchMessages(true);
        const interval = setInterval(() => {
            fetchMessages(false);
        }, 7000);
        return () => clearInterval(interval);
    }, [order?._id]);

    useEffect(() => {
        scrollToBottom();
    }, [messages, channelMode]);

    const handleSendMessage = async (e) => {
        e?.preventDefault();
        if ((!inputText.trim() && !selectedFile) || sending) return;

        setSending(true);
        try {
            const token = userInfo?.token || localStorage.getItem('token');
            const formData = new FormData();
            formData.append('message', inputText.trim());
            formData.append('messageType', isStaff ? channelMode : 'client');

            if (selectedFile) {
                formData.append('file', selectedFile);
            }

            const res = await axios.post(`/api/orders/${order._id}/messages`, formData, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'multipart/form-data'
                }
            });

            setMessages(prev => [...prev, res.data]);
            setInputText('');
            setSelectedFile(null);
            if (fileInputRef.current) fileInputRef.current.value = '';
            scrollToBottom();
        } catch (err) {
            console.error('[OrderChat] Send error:', err);
            setErrorMsg(err.response?.data?.message || 'Failed to send message');
        } finally {
            setSending(false);
        }
    };

    // Filter messages based on active tab view for staff
    const displayedMessages = messages.filter(m => {
        if (!isStaff) return m.messageType === 'client';
        if (channelMode === 'all') return true;
        return m.messageType === channelMode;
    });

    const clientMessagesCount = messages.filter(m => m.messageType === 'client').length;
    const internalMessagesCount = messages.filter(m => m.messageType === 'internal').length;

    // Quick predefined reply snippets
    const staffQuickReplies = [
        "Documents verified. Processing on the government portal now.",
        "Please provide the password for the uploaded PDF.",
        "Filing submitted successfully. Awaiting acknowledgment receipt.",
        "Assigned to Checker for final audit."
    ];

    const customerQuickReplies = [
        "Uploaded the requested documents.",
        "Could you please share an estimated timeline?",
        "Everything looks good. Please proceed."
    ];

    const quickReplies = isStaff ? staffQuickReplies : customerQuickReplies;

    const getRoleBadge = (role) => {
        switch ((role || '').toLowerCase()) {
            case 'admin':
                return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-700 uppercase">Admin</span>;
            case 'employee':
                return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-100 text-blue-700 uppercase">Team</span>;
            case 'freelancer':
                return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-700 uppercase">Specialist</span>;
            default:
                return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-700 uppercase">Client</span>;
        }
    };

    return (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm flex flex-col h-[700px] overflow-hidden">
            {/* 1. Header & Channel Selector */}
            <div className="bg-slate-900 text-white px-6 py-4 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-rose-500 flex items-center justify-center text-white shadow-md">
                        <MessageSquare size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2">
                            <h3 className="font-bold text-base text-white">
                                {isStaff ? 'Order Communications & Team Hub' : 'Order Support & Advisor Chat'}
                            </h3>
                            <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                Live
                            </span>
                        </div>
                        <p className="text-xs text-slate-400">
                            {order?.serviceName} • #{order?._id?.slice(-8)?.toUpperCase()}
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <button
                        onClick={() => { setRefreshing(true); fetchMessages(false); }}
                        className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-all text-xs flex items-center gap-1.5"
                        title="Refresh Messages"
                    >
                        <RefreshCw size={14} className={refreshing ? 'animate-spin text-indigo-400' : ''} />
                        <span className="hidden sm:inline">Refresh</span>
                    </button>
                </div>
            </div>

            {/* 2. Staff Channel Tabs (Client vs Internal) */}
            {isStaff && (
                <div className="bg-slate-100/80 px-6 py-2.5 flex items-center justify-between border-b border-slate-200">
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setChannelMode('client')}
                            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all ${
                                channelMode === 'client'
                                    ? 'bg-emerald-600 text-white shadow-sm'
                                    : 'bg-white text-slate-700 hover:bg-slate-200/70 border border-slate-300/70'
                            }`}
                        >
                            <MessageSquare size={14} />
                            <span>Client Discussion</span>
                            <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                                channelMode === 'client' ? 'bg-white/25 text-white' : 'bg-slate-200 text-slate-700'
                            }`}>
                                {clientMessagesCount}
                            </span>
                        </button>

                        <button
                            onClick={() => setChannelMode('internal')}
                            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all ${
                                channelMode === 'internal'
                                    ? 'bg-amber-600 text-white shadow-sm'
                                    : 'bg-white text-slate-700 hover:bg-slate-200/70 border border-slate-300/70'
                            }`}
                        >
                            <Lock size={13} />
                            <span>Internal Team Notes</span>
                            <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                                channelMode === 'internal' ? 'bg-white/25 text-white' : 'bg-slate-200 text-slate-700'
                            }`}>
                                {internalMessagesCount}
                            </span>
                        </button>

                        <button
                            onClick={() => setChannelMode('all')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                                channelMode === 'all'
                                    ? 'bg-slate-800 text-white'
                                    : 'bg-white text-slate-600 hover:bg-slate-200/70 border border-slate-300/70'
                            }`}
                        >
                            All ({messages.length})
                        </button>
                    </div>

                    <div className="hidden md:flex items-center gap-1.5 text-[11px] text-slate-500 font-medium">
                        {channelMode === 'internal' ? (
                            <span className="flex items-center gap-1 text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                                <Lock size={12} /> Confidential • Customer cannot see these notes
                            </span>
                        ) : (
                            <span className="flex items-center gap-1 text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                                <MessageSquare size={12} /> Public • Customer can read and reply
                            </span>
                        )}
                    </div>
                </div>
            )}

            {/* 3. Messages Message Stream */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-slate-50/50">
                {loading ? (
                    <div className="h-full flex flex-col items-center justify-center text-slate-400 gap-3">
                        <RefreshCw size={24} className="animate-spin text-indigo-500" />
                        <p className="text-xs font-medium">Loading conversation...</p>
                    </div>
                ) : displayedMessages.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-center p-8 max-w-md mx-auto">
                        <div className="w-14 h-14 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center mb-3">
                            {channelMode === 'internal' ? <Lock size={26} /> : <MessageSquare size={26} />}
                        </div>
                        <h4 className="font-bold text-slate-800 text-sm">
                            {channelMode === 'internal' ? 'No Internal Notes Yet' : 'Start the Conversation'}
                        </h4>
                        <p className="text-xs text-slate-500 mt-1">
                            {channelMode === 'internal'
                                ? 'Leave private notes, execution remarks, or tags for Maker, Checker, and Project Manager.'
                                : isStaff
                                    ? 'Send updates, document instructions, or status notes directly to the client.'
                                    : 'Have a query or need an update on your order? Send a message to our team below.'}
                        </p>
                    </div>
                ) : (
                    displayedMessages.map((msg, index) => {
                        const isMe = msg.sender?._id === userInfo?._id || msg.sender === userInfo?._id;
                        const isInternal = msg.messageType === 'internal';

                        return (
                            <div 
                                key={msg._id || index}
                                className={`flex flex-col ${isMe ? 'items-end' : 'items-start'} max-w-full`}
                            >
                                <div className="flex items-center gap-2 mb-1 px-1">
                                    <span className="text-xs font-bold text-slate-700">
                                        {isMe ? 'You' : msg.senderName || msg.sender?.name || 'User'}
                                    </span>
                                    {getRoleBadge(msg.senderRole || msg.sender?.role)}
                                    {isInternal && (
                                        <span className="flex items-center gap-0.5 text-[10px] font-bold px-1.5 py-0.2 rounded bg-amber-500 text-white">
                                            <Lock size={10} /> STAFF NOTE
                                        </span>
                                    )}
                                    <span className="text-[10px] text-slate-400">
                                        {new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                    </span>
                                </div>

                                <div 
                                    className={`relative p-3.5 rounded-2xl max-w-[85%] sm:max-w-[70%] shadow-sm text-sm break-words ${
                                        isInternal
                                            ? 'bg-amber-50/90 text-amber-950 border border-amber-300/80 rounded-tl-sm'
                                            : isMe
                                                ? 'bg-indigo-600 text-white rounded-tr-sm'
                                                : 'bg-white text-slate-800 border border-slate-200/90 rounded-tl-sm'
                                    }`}
                                >
                                    {msg.message && (
                                        <p className="whitespace-pre-wrap leading-relaxed">
                                            {msg.message}
                                        </p>
                                    )}

                                    {/* Attachments */}
                                    {Array.isArray(msg.attachments) && msg.attachments.length > 0 && (
                                        <div className={`mt-2.5 pt-2 space-y-1.5 border-t ${
                                            isInternal ? 'border-amber-200' : isMe ? 'border-indigo-500/50' : 'border-slate-100'
                                        }`}>
                                            {msg.attachments.map((att, attIdx) => (
                                                <a
                                                    key={attIdx}
                                                    href={att.url}
                                                    target="_blank"
                                                    rel="noreferrer"
                                                    className={`flex items-center gap-2 p-2 rounded-lg text-xs transition-all ${
                                                        isMe 
                                                            ? 'bg-indigo-700/60 hover:bg-indigo-700 text-white' 
                                                            : 'bg-slate-100 hover:bg-slate-200 text-slate-800'
                                                    }`}
                                                >
                                                    <FileText size={14} className="shrink-0" />
                                                    <span className="truncate flex-1 font-medium">{att.name || 'Attachment'}</span>
                                                    <Download size={13} className="shrink-0 opacity-70" />
                                                </a>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        );
                    })
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* 4. Quick Suggestions / Common Replies */}
            <div className="px-6 py-2 bg-slate-50 border-t border-slate-200 flex items-center gap-2 overflow-x-auto no-scrollbar">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider shrink-0">
                    Quick:
                </span>
                {quickReplies.map((reply, idx) => (
                    <button
                        key={idx}
                        onClick={() => setInputText(reply)}
                        className="text-xs text-slate-600 bg-white hover:bg-slate-100 hover:text-indigo-600 px-3 py-1 rounded-full border border-slate-200 transition-all shrink-0 font-medium shadow-2xs"
                    >
                        {reply}
                    </button>
                ))}
            </div>

            {/* 5. Attachment Preview Bar */}
            {selectedFile && (
                <div className="px-6 py-2 bg-indigo-50/80 border-t border-indigo-100 flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs text-indigo-900 font-medium truncate">
                        <Paperclip size={14} className="text-indigo-600 shrink-0" />
                        <span className="truncate">{selectedFile.name}</span>
                        <span className="text-indigo-400 text-[10px]">
                            ({(selectedFile.size / 1024).toFixed(0)} KB)
                        </span>
                    </div>
                    <button
                        onClick={() => {
                            setSelectedFile(null);
                            if (fileInputRef.current) fileInputRef.current.value = '';
                        }}
                        className="text-indigo-600 hover:text-rose-600 p-1"
                    >
                        <X size={14} />
                    </button>
                </div>
            )}

            {/* 6. Message Input Footer */}
            <form onSubmit={handleSendMessage} className="p-4 bg-white border-t border-slate-200">
                {errorMsg && (
                    <div className="mb-2 text-xs text-rose-600 font-medium flex items-center gap-1.5">
                        <AlertCircle size={14} /> {errorMsg}
                    </div>
                )}

                <div className="flex items-end gap-2">
                    {/* Hidden file input */}
                    <input
                        type="file"
                        ref={fileInputRef}
                        className="hidden"
                        onChange={(e) => {
                            if (e.target.files?.[0]) setSelectedFile(e.target.files[0]);
                        }}
                    />

                    <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        className={`p-2.5 rounded-xl border transition-all ${
                            selectedFile 
                                ? 'bg-indigo-50 border-indigo-300 text-indigo-600' 
                                : 'bg-slate-50 border-slate-200 hover:bg-slate-100 text-slate-500'
                        }`}
                        title="Attach File"
                    >
                        <Paperclip size={18} />
                    </button>

                    <div className="flex-1 relative">
                        <textarea
                            value={inputText}
                            onChange={(e) => setInputText(e.target.value)}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSendMessage();
                                }
                            }}
                            rows={1}
                            placeholder={
                                isStaff
                                    ? channelMode === 'internal'
                                        ? 'Write a private internal note for the team...'
                                        : 'Type a message to the client (press Enter to send)...'
                                    : 'Type your message or question for our team...'
                            }
                            className={`w-full text-sm px-4 py-2.5 rounded-xl border focus:outline-none resize-none transition-all ${
                                isStaff && channelMode === 'internal'
                                    ? 'border-amber-300 bg-amber-50/40 focus:ring-2 focus:ring-amber-400 focus:bg-white'
                                    : 'border-slate-200 focus:ring-2 focus:ring-indigo-500 focus:border-transparent'
                            }`}
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={sending || (!inputText.trim() && !selectedFile)}
                        className={`px-5 py-2.5 rounded-xl font-bold text-sm text-white flex items-center gap-2 shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
                            isStaff && channelMode === 'internal'
                                ? 'bg-amber-600 hover:bg-amber-700'
                                : 'bg-indigo-600 hover:bg-indigo-700'
                        }`}
                    >
                        {sending ? (
                            <RefreshCw size={16} className="animate-spin" />
                        ) : (
                            <>
                                <span>Send</span>
                                <Send size={15} />
                            </>
                        )}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default OrderChatTab;
