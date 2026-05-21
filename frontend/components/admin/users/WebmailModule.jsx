import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { Plus, Trash2, Key, RefreshCw, AlertCircle, Shield, Copy, Check, ExternalLink } from 'lucide-react';

const WebmailModule = ({ token }) => {
  const [webmails, setWebmails] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  
  // Create Form State
  const [emailPrefix, setEmailPrefix] = useState('');
  const [emailDomain, setEmailDomain] = useState('vrhere.in');
  const [customDomain, setCustomDomain] = useState('');
  const [forwardTo, setForwardTo] = useState('');
  const [password, setPassword] = useState('');
  const [showCustomDomainInput, setShowCustomDomainInput] = useState(false);

  // Edit / Password Update States
  const [editingId, setEditingId] = useState('');
  const [editForwardTo, setEditForwardTo] = useState('');
  const [changingPasswordId, setChangingPasswordId] = useState('');
  const [newPassword, setNewPassword] = useState('');

  // Copy State
  const [copiedText, setCopiedText] = useState('');

  // Diagnostics State
  const [diagnostics, setDiagnostics] = useState(null);
  const [isDiagnosing, setIsDiagnosing] = useState(false);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);

  // Header authorization config
  const config = useMemo(() => ({ headers: { Authorization: `Bearer ${token}` } }), [token]);

  const activeDomain = showCustomDomainInput ? customDomain.trim().toLowerCase() : emailDomain;

  // Fetch webmail accounts
  const fetchWebmails = async () => {
    setIsLoading(true);
    try {
      const { data } = await axios.get('/api/webmail', config);
      setWebmails(data || []);
    } catch (err) {
      console.error('Failed to fetch webmail accounts:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunDiagnostics = async () => {
    setIsDiagnosing(true);
    setShowDiagnostics(true);
    try {
      const { data } = await axios.get('/api/webmail/diagnostics', config);
      setDiagnostics(data);
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to fetch diagnostics.');
      setShowDiagnostics(false);
    } finally {
      setIsDiagnosing(false);
    }
  };

  const handleSyncServer = async () => {
    setIsSyncing(true);
    try {
      const { data } = await axios.post('/api/webmail/sync', {}, config);
      alert(data.message || 'Mailboxes synchronized successfully!');
      fetchWebmails();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to synchronize mailboxes on the server.');
    } finally {
      setIsSyncing(false);
    }
  };

  useEffect(() => {
    fetchWebmails();
  }, [config]);

  // Create new webmail mapping
  const handleCreate = async (e) => {
    e.preventDefault();
    if (!emailPrefix || !activeDomain || !forwardTo || !password) {
      alert('Please fill out all fields.');
      return;
    }

    const fullEmail = `${emailPrefix.trim().toLowerCase()}@${activeDomain}`;
    setIsCreating(true);

    try {
      await axios.post('/api/webmail', {
        email: fullEmail,
        forwardTo: forwardTo.trim().toLowerCase(),
        password
      }, config);

      alert(`Webmail account ${fullEmail} successfully created!`);
      
      // Clear form
      setEmailPrefix('');
      setForwardTo('');
      setPassword('');
      setCustomDomain('');
      setShowCustomDomainInput(false);
      setEmailDomain('vrhere.in');
      
      fetchWebmails();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to create webmail account.');
    } finally {
      setIsCreating(false);
    }
  };

  // Toggle active/inactive status
  const handleToggleActive = async (id, currentStatus) => {
    try {
      await axios.put(`/api/webmail/${id}`, { isActive: !currentStatus }, config);
      fetchWebmails();
    } catch (err) {
      alert('Failed to update webmail status.');
    }
  };

  // Save forwarding target edit
  const handleSaveForwarding = async (id) => {
    if (!editForwardTo) return;
    try {
      await axios.put(`/api/webmail/${id}`, { forwardTo: editForwardTo.trim().toLowerCase() }, config);
      setEditingId('');
      setEditForwardTo('');
      fetchWebmails();
    } catch (err) {
      alert('Failed to update forwarding email.');
    }
  };

  // Save password update
  const handleSavePassword = async (id) => {
    if (!newPassword) return;
    try {
      await axios.put(`/api/webmail/${id}`, { password: newPassword }, config);
      setChangingPasswordId('');
      setNewPassword('');
      alert('Password updated successfully!');
      fetchWebmails();
    } catch (err) {
      alert('Failed to update password.');
    }
  };

  // Delete webmail account
  const handleDelete = async (wm) => {
    if (!window.confirm(`Are you sure you want to permanently delete ${wm.email}? This will stop all mail forwarding and SMTP access for this email.`)) {
      return;
    }

    try {
      await axios.delete(`/api/webmail/${wm._id}`, config);
      fetchWebmails();
    } catch (err) {
      alert('Failed to delete webmail account.');
    }
  };

  // Copy helper
  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(''), 2000);
  };

  return (
    <div className="space-y-6">
      
      {/* ACTIONS TOOLBAR */}
      <div className="flex flex-wrap justify-end gap-2 p-2">
        <button 
          onClick={handleRunDiagnostics}
          disabled={isDiagnosing}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-700 text-white text-xs font-black uppercase tracking-widest transition active:scale-95 disabled:opacity-50 shadow-md"
        >
          <Shield size={14} className={isDiagnosing ? 'animate-pulse' : ''} />
          {isDiagnosing ? 'Running...' : 'Run Diagnostics'}
        </button>
        <button 
          onClick={handleSyncServer}
          disabled={isSyncing}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-black uppercase tracking-widest transition active:scale-95 disabled:opacity-50 shadow-md"
        >
          <RefreshCw size={14} className={isSyncing ? 'animate-spin' : ''} />
          {isSyncing ? 'Syncing...' : 'Sync VPS Config'}
        </button>
        <button 
          onClick={fetchWebmails}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-black uppercase tracking-widest transition active:scale-95 disabled:opacity-50 shadow-sm"
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
          Refresh List
        </button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        
        {/* ADD WEBMAIL FORM */}
        <div className="xl:col-span-1 space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm p-6">
            <h3 className="text-lg font-extrabold text-slate-900 mb-2 flex items-center gap-2">
              <Plus className="text-indigo-600" size={20} /> Create Webmail
            </h3>
            <p className="text-xs text-slate-500 mb-5">Configure forwarding rules and SMTP relay settings for a custom domain mailbox.</p>

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-black text-slate-500 uppercase tracking-widest mb-1.5">Custom Email Address</label>
                <div className="flex gap-2">
                  <input 
                    type="text" 
                    value={emailPrefix}
                    onChange={(e) => setEmailPrefix(e.target.value.replace(/[^a-zA-Z0-9.-]/g, ''))}
                    placeholder="e.g. info" 
                    required
                    className="flex-1 p-2.5 border rounded-xl border-slate-300 bg-white text-sm focus:ring-2 focus:ring-indigo-600/20 focus:border-indigo-600 outline-none"
                  />
                  <span className="self-center text-slate-400 font-bold">@</span>
                  {!showCustomDomainInput ? (
                    <select
                      value={emailDomain}
                      onChange={(e) => {
                        if (e.target.value === 'custom') {
                          setShowCustomDomainInput(true);
                          setEmailDomain('');
                        } else {
                          setEmailDomain(e.target.value);
                        }
                      }}
                      className="p-2.5 border rounded-xl border-slate-300 bg-white text-sm focus:ring-2 focus:ring-indigo-600/20 focus:border-indigo-600 outline-none w-[140px]"
                    >
                      <option value="vrhere.in">vrhere.in</option>
                      <option value="custom">+ Custom...</option>
                    </select>
                  ) : (
                    <div className="flex gap-1">
                      <input
                        type="text"
                        value={customDomain}
                        onChange={(e) => setCustomDomain(e.target.value.replace(/[^a-zA-Z0-9.-]/g, ''))}
                        placeholder="domain.com"
                        required
                        className="p-2.5 border rounded-xl border-slate-300 bg-white text-sm focus:ring-2 focus:ring-indigo-600/20 focus:border-indigo-600 outline-none w-[110px]"
                      />
                      <button 
                        type="button"
                        onClick={() => {
                          setShowCustomDomainInput(false);
                          setEmailDomain('vrhere.in');
                          setCustomDomain('');
                        }}
                        className="px-2 text-slate-400 hover:text-slate-600 text-xs font-bold"
                      >
                        Reset
                      </button>
                    </div>
                  )}
                </div>
              </div>

              <div>
                <label className="block text-xs font-black text-slate-500 uppercase tracking-widest mb-1.5">Forward Inbound Mails To</label>
                <input 
                  type="email" 
                  value={forwardTo}
                  onChange={(e) => setForwardTo(e.target.value)}
                  placeholder="e.g. yourname@gmail.com" 
                  required
                  className="w-full p-2.5 border rounded-xl border-slate-300 bg-white text-sm focus:ring-2 focus:ring-indigo-600/20 focus:border-indigo-600 outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-black text-slate-500 uppercase tracking-widest mb-1.5">SMTP Authentication Password</label>
                <input 
                  type="password" 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Secure password for Gmail SMTP" 
                  required
                  className="w-full p-2.5 border rounded-xl border-slate-300 bg-white text-sm focus:ring-2 focus:ring-indigo-600/20 focus:border-indigo-600 outline-none"
                />
              </div>

              <button 
                type="submit" 
                disabled={isCreating}
                className="w-full mt-2 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white text-sm font-black uppercase tracking-widest shadow-md transition active:scale-95 disabled:opacity-50"
              >
                {isCreating ? 'Creating Rule...' : 'Generate Webmail Rule'}
              </button>
            </form>
          </div>

          {/* SYSTEM REQUIREMENTS HIGHLIGHT */}
          <div className="rounded-2xl border border-amber-100 bg-amber-50/50 p-5">
            <div className="flex gap-3">
              <AlertCircle className="text-amber-600 flex-shrink-0 mt-0.5" size={18} />
              <div>
                <h4 className="text-xs font-black uppercase tracking-wider text-amber-800">VPS Sync Notice</h4>
                <p className="text-[11px] text-amber-700/90 leading-relaxed mt-1">
                  New mail mappings and passwords take up to **5 minutes** to sync onto the live VPS mail servers. All generated files are securely mapped to local configs on the server.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* WEBMAIL RULES LIST */}
        <div className="xl:col-span-2 space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm p-6">
            <h3 className="text-lg font-extrabold text-slate-900 mb-4">Active Mail Mappings</h3>
            
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm min-w-[620px]">
                <thead>
                  <tr className="border-b border-slate-100 text-xs font-black uppercase text-slate-400">
                    <th className="pb-3">Custom Mailbox</th>
                    <th className="pb-3">Forward Target</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {isLoading && (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-slate-400 italic">
                        Syncing live database mappings...
                      </td>
                    </tr>
                  )}
                  {!isLoading && webmails.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-slate-400 italic">
                        No custom email mapping rules created yet.
                      </td>
                    </tr>
                  )}
                  {!isLoading && webmails.map((wm) => {
                    const isEditing = editingId === wm._id;
                    const isChangingPassword = changingPasswordId === wm._id;
                    return (
                      <tr key={wm._id} className="group hover:bg-slate-50/40">
                        <td className="py-3.5 font-bold text-slate-800">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-indigo-500" />
                            {wm.email}
                          </div>
                        </td>
                        <td className="py-3.5">
                          {isEditing ? (
                            <div className="flex gap-1.5 items-center">
                              <input 
                                type="email" 
                                value={editForwardTo} 
                                onChange={(e) => setEditForwardTo(e.target.value)} 
                                className="p-1 border rounded border-slate-300 text-xs bg-white w-48 outline-none focus:ring-1 focus:ring-indigo-500"
                              />
                              <button onClick={() => handleSaveForwarding(wm._id)} className="px-2 py-0.5 bg-indigo-600 text-white rounded text-[10px] font-black uppercase">Save</button>
                              <button onClick={() => setEditingId('')} className="px-2 py-0.5 bg-slate-200 text-slate-700 rounded text-[10px] font-black uppercase">Cancel</button>
                            </div>
                          ) : (
                            <span className="text-slate-500 font-medium">{wm.forwardTo}</span>
                          )}
                        </td>
                        <td className="py-3.5">
                          <button 
                            onClick={() => handleToggleActive(wm._id, wm.isActive)}
                            className={`px-2.5 py-0.5 rounded-md text-[10px] font-black uppercase tracking-wider ${
                              wm.isActive 
                                ? 'bg-emerald-50 text-emerald-700 border border-emerald-100 hover:bg-emerald-100' 
                                : 'bg-slate-100 text-slate-500 border border-slate-200 hover:bg-slate-200'
                            }`}
                          >
                            {wm.isActive ? 'Active' : 'Inactive'}
                          </button>
                        </td>
                        <td className="py-3.5 text-right">
                          {isChangingPassword ? (
                            <div className="inline-flex gap-1.5 items-center">
                              <input 
                                type="password" 
                                placeholder="New password"
                                value={newPassword} 
                                onChange={(e) => setNewPassword(e.target.value)} 
                                className="p-1 border rounded border-slate-300 text-xs bg-white w-32 outline-none focus:ring-1 focus:ring-indigo-500"
                              />
                              <button onClick={() => handleSavePassword(wm._id)} className="px-2 py-0.5 bg-indigo-600 text-white rounded text-[10px] font-black uppercase">Apply</button>
                              <button onClick={() => setChangingPasswordId('')} className="px-2 py-0.5 bg-slate-200 text-slate-700 rounded text-[10px] font-black uppercase">Cancel</button>
                            </div>
                          ) : (
                            <div className="flex justify-end gap-2">
                              {!isEditing && (
                                <>
                                  <button 
                                    onClick={() => { setEditingId(wm._id); setEditForwardTo(wm.forwardTo); }}
                                    className="p-1.5 rounded-lg border border-slate-100 hover:border-indigo-100 hover:bg-indigo-50 text-slate-400 hover:text-indigo-600 transition"
                                    title="Edit Forwarding Address"
                                  >
                                    <ExternalLink size={14} />
                                  </button>
                                  <button 
                                    onClick={() => setChangingPasswordId(wm._id)}
                                    className="p-1.5 rounded-lg border border-slate-100 hover:border-indigo-100 hover:bg-indigo-50 text-slate-400 hover:text-indigo-600 transition"
                                    title="Update Password"
                                  >
                                    <Key size={14} />
                                  </button>
                                </>
                              )}
                              <button 
                                onClick={() => handleDelete(wm)}
                                className="p-1.5 rounded-lg border border-slate-100 hover:border-rose-100 hover:bg-rose-50 text-slate-400 hover:text-rose-600 transition"
                                title="Delete Rule"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* DETAILED GMAIL INTEGRATION GUIDE */}
      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm p-6">
        <h3 className="text-lg font-extrabold text-slate-900 mb-2 flex items-center gap-2">
          <Shield className="text-indigo-600" size={22} /> Gmail "Send Mail As" Configuration Guide
        </h3>
        <p className="text-xs text-slate-500 mb-6">
          Learn how to authenticate outgoing emails from your Gmail account using your VPS custom domain SMTP setup so recipients see your brand email.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-4">
            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 font-bold text-xs flex items-center justify-center flex-shrink-0 mt-0.5">1</div>
              <div>
                <p className="text-sm font-bold text-slate-800">Open Gmail Settings</p>
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                  Log into your primary Gmail. Click the **Gear Icon** in the top right, select **"See all settings"**, and navigate to the **"Accounts and Import"** tab.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 font-bold text-xs flex items-center justify-center flex-shrink-0 mt-0.5">2</div>
              <div>
                <p className="text-sm font-bold text-slate-800">Add another email address</p>
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                  Scroll down to the **"Send mail as:"** section and click **"Add another email address"**. A yellow popup window will appear. Enter your Name and the custom email address (e.g. `info@vrhere.in`). Leave *"Treat as an alias"* checked, then click **"Next Step"**.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 font-bold text-xs flex items-center justify-center flex-shrink-0 mt-0.5">3</div>
              <div>
                <p className="text-sm font-bold text-slate-800">Configure SMTP Server Details</p>
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                  Fill in the SMTP relay details listed in the panel on the right. Enter your full custom email address as the Username and the SMTP password you specified during creation. Click **"Add Account"**.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 font-bold text-xs flex items-center justify-center flex-shrink-0 mt-0.5">4</div>
              <div>
                <p className="text-sm font-bold text-slate-800">Verify Account</p>
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                  Gmail will send a verification code to your custom email. Since incoming mail is automatically forwarded, **check the inbox of your target Gmail address** for the code. Enter the code in the popup window and click **"Verify"**.
                </p>
              </div>
            </div>
          </div>

          {/* QUICK COPY REFERENCE CARD */}
          <div className="rounded-2xl bg-slate-900 text-slate-300 p-6 flex flex-col justify-between border border-slate-800 relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-5">
              <Shield size={120} />
            </div>

            <h4 className="text-xs font-black uppercase tracking-widest text-cyan-300 mb-4">SMTP Relay Parameters</h4>

            <div className="space-y-3 flex-1 text-xs">
              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="font-semibold text-slate-400">SMTP Server</span>
                <div className="flex items-center gap-2 font-mono text-[11px] text-white">
                  <span>vrhere.in</span>
                  <button 
                    onClick={() => handleCopy('vrhere.in')} 
                    className="p-1 text-slate-500 hover:text-white transition"
                  >
                    {copiedText === 'vrhere.in' ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                  </button>
                </div>
              </div>

              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="font-semibold text-slate-400">Port</span>
                <span className="font-mono text-[11px] text-white">587</span>
              </div>

              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="font-semibold text-slate-400">Secured Connection</span>
                <span className="font-mono text-[11px] text-white">TLS / STARTTLS (Recommended)</span>
              </div>

              <div className="flex justify-between items-center py-2">
                <span className="font-semibold text-slate-400">Username</span>
                <span className="font-mono text-[11px] text-emerald-400">Your full custom email address</span>
              </div>
            </div>

            <div className="mt-5 p-3 rounded-xl bg-slate-800/40 border border-slate-800 text-[10px] text-slate-400 leading-relaxed">
              *Pro Tip: For all your custom domains (e.g. any domain configured on this VPS), you can always use **`vrhere.in`** as the working SMTP server with your custom mailbox username & password!
            </div>
          </div>
        </div>
      </div>

      {/* EMAIL DELIVERABILITY & DNS AUTHENTICATION GUIDE */}
      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm p-6">
        <h3 className="text-lg font-extrabold text-slate-900 mb-2 flex items-center gap-2">
          <Shield className="text-indigo-600 animate-pulse" size={22} /> Email Authentication & Deliverability (SPF, DKIM, DMARC)
        </h3>
        <p className="text-xs text-slate-500 mb-6">
          Configure these TXT DNS records for your domain (**vrhere.in**) at your domain registrar (GoDaddy, Namecheap, Cloudflare, etc.) to sign all outbound emails, build domain reputation, and ensure 100% deliverability directly to primary inboxes.
        </p>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* SPF RECORD CARD */}
          <div className="p-5 rounded-2xl border border-slate-100 bg-slate-50/50 hover:bg-slate-50 transition flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700">SPF Record</span>
                <span className="text-[10px] text-slate-400 font-medium">Domain TXT</span>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed mb-4">
                Declares your VPS IP address as a valid sender. This prevents malicious servers from sending spoofed emails using your name.
              </p>
            </div>
            
            <div className="space-y-2.5 pt-3 border-t border-slate-100 font-mono text-[11px]">
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Host / Name</span>
                <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200">@</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Type</span>
                <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200">TXT</span>
              </div>
              <div className="flex justify-between items-center gap-4">
                <span className="text-slate-400 font-semibold flex-shrink-0">Value</span>
                <div className="flex items-center gap-1.5 overflow-hidden">
                  <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200 truncate max-w-[150px]">v=spf1 ip4:147.93.107.21 ~all</span>
                  <button 
                    onClick={() => handleCopy('v=spf1 ip4:147.93.107.21 ~all')} 
                    className="p-1 text-slate-400 hover:text-indigo-600 transition flex-shrink-0"
                  >
                    {copiedText === 'v=spf1 ip4:147.93.107.21 ~all' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* DKIM RECORD CARD */}
          <div className="p-5 rounded-2xl border border-slate-100 bg-slate-50/50 hover:bg-slate-50 transition flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-cyan-50 text-cyan-700">DKIM Record</span>
                <span className="text-[10px] text-slate-400 font-medium">Domain TXT</span>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed mb-4">
                Signs all outgoing emails with a unique cryptographic signature. You can view and copy your public DKIM key directly inside the VPS diagnostics panel.
              </p>
            </div>
            
            <div className="space-y-2.5 pt-3 border-t border-slate-100 font-mono text-[11px]">
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Host / Name</span>
                <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200">mail._domainkey</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Type</span>
                <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200">TXT</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Value</span>
                <button 
                  onClick={handleRunDiagnostics}
                  className="text-[10px] text-indigo-600 hover:text-indigo-800 font-extrabold uppercase tracking-wide flex items-center gap-1 active:scale-95 transition"
                >
                  <Shield size={10} /> View in Diagnostics
                </button>
              </div>
            </div>
          </div>

          {/* DMARC POLICY CARD */}
          <div className="p-5 rounded-2xl border border-slate-100 bg-slate-50/50 hover:bg-slate-50 transition flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-rose-50 text-rose-700">DMARC Policy</span>
                <span className="text-[10px] text-slate-400 font-medium">Domain TXT</span>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed mb-4">
                Establishes how external providers like Google and Yahoo handle messages claiming to be from your domain that fail authentication checks.
              </p>
            </div>
            
            <div className="space-y-2.5 pt-3 border-t border-slate-100 font-mono text-[11px]">
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Host / Name</span>
                <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200">_dmarc</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-semibold">Type</span>
                <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200">TXT</span>
              </div>
              <div className="flex justify-between items-center gap-4">
                <span className="text-slate-400 font-semibold flex-shrink-0">Value</span>
                <div className="flex items-center gap-1.5 overflow-hidden">
                  <span className="text-slate-800 font-bold bg-white px-2 py-0.5 rounded border border-slate-200 truncate max-w-[150px]">v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@vrhere.in</span>
                  <button 
                    onClick={() => handleCopy('v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@vrhere.in')} 
                    className="p-1 text-slate-400 hover:text-indigo-600 transition flex-shrink-0"
                  >
                    {copiedText === 'v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@vrhere.in' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* DIAGNOSTICS MODAL/PANEL */}
      {showDiagnostics && (
        <div className="rounded-2xl border border-slate-200 bg-slate-900 text-white shadow-xl p-6 space-y-4 mt-6">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3">
            <h3 className="text-lg font-extrabold text-cyan-400 flex items-center gap-2">
              <Shield size={20} /> VPS Mail Server Diagnostics
            </h3>
            <button 
              onClick={() => setShowDiagnostics(false)} 
              className="text-slate-400 hover:text-white text-xs font-black uppercase tracking-widest bg-slate-800 px-3 py-1 rounded-lg transition"
            >
              Close
            </button>
          </div>
          
          {isDiagnosing && (
            <div className="py-8 text-center text-slate-400 italic flex flex-col items-center justify-center gap-3">
              <RefreshCw size={24} className="animate-spin text-cyan-400" />
              <span>Querying VPS postfix mail queue and system status...</span>
            </div>
          )}
          
          {!isDiagnosing && diagnostics && (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 text-xs">
              <div className="space-y-4">
                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Mail Queue (mailq / postqueue)</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[180px] text-white">
                    {diagnostics.mailq || 'Mail queue is empty.'}
                  </pre>
                </div>

                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Postfix Configured Virtual Aliases (/etc/postfix/virtual)</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[150px] text-white whitespace-pre-wrap">
                    {diagnostics.postfixVirtual || 'No aliases configured.'}
                  </pre>
                </div>

                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Dovecot Configured Virtual Users (/etc/dovecot/users)</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[150px] text-white whitespace-pre-wrap">
                    {diagnostics.dovecotUsers || 'No virtual users configured.'}
                  </pre>
                </div>

                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">OpenDKIM Public Key Configuration (Copy for TXT DNS Setup)</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[180px] text-emerald-400 whitespace-pre-wrap">
                    {diagnostics.dkimKey || 'No opendkim key file located.'}
                  </pre>
                </div>

                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Live DNS Record Lookup from VPS</h4>
                  <div className="space-y-2 bg-black/60 border border-slate-800 rounded-xl p-3 text-[11px] font-mono leading-relaxed text-white">
                    <div>
                      <span className="text-slate-400 font-bold">SPF Record (TXT @):</span>
                      <pre className="mt-1 p-1 bg-black/40 rounded max-h-[80px] overflow-auto text-yellow-300">{diagnostics.spfDns?.trim() || 'No record found.'}</pre>
                    </div>
                    <div>
                      <span className="text-slate-400 font-bold">DMARC Record (TXT _dmarc):</span>
                      <pre className="mt-1 p-1 bg-black/40 rounded max-h-[80px] overflow-auto text-yellow-300">{diagnostics.dmarcDns?.trim() || 'No record found.'}</pre>
                    </div>
                    <div>
                      <span className="text-slate-400 font-bold">DKIM Record (TXT mail._domainkey):</span>
                      <pre className="mt-1 p-1 bg-black/40 rounded max-h-[80px] overflow-auto text-yellow-300">{diagnostics.dkimDns?.trim() || 'No record found.'}</pre>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Postfix Status</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[150px] text-white">
                    {diagnostics.postfixStatus}
                  </pre>
                </div>
                
                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Dovecot Status</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[150px] text-white">
                    {diagnostics.dovecotStatus}
                  </pre>
                </div>

                <div>
                  <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-2">Dovecot Config (doveconf -n)</h4>
                  <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-x-auto text-[11px] font-mono leading-relaxed max-h-[250px] text-white whitespace-pre-wrap">
                    {diagnostics.dovecotConf || 'No Dovecot config dump available.'}
                  </pre>
                </div>
              </div>
              
              <div className="space-y-2">
                <h4 className="font-black text-cyan-300 uppercase tracking-wider mb-1 flex justify-between">
                  <span>Mail Log (tail /var/log/mail.log)</span>
                  <span className="text-[10px] text-slate-500 font-normal normal-case">Shows recent mail transmission logs</span>
                </h4>
                <pre className="p-3 bg-black/60 border border-slate-800 rounded-xl overflow-auto text-[11px] font-mono leading-relaxed h-[620px] text-white whitespace-pre-wrap">
                  {diagnostics.mailLog}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  );
};

export default WebmailModule;
