import React from 'react';
import { Pencil, Power, Send, Trash2, ShieldCheck } from 'lucide-react';

const formatImageUrl = (url) => {
  if (!url || typeof url !== 'string') return '';
  if (url.includes('drive.google.com/file/d/')) {
    const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (match && match[1]) {
      return `https://lh3.googleusercontent.com/d/${match[1]}`;
    }
  }
  if (url.includes('drive.google.com/open?id=')) {
    const match = url.match(/id=([a-zA-Z0-9_-]+)/);
    if (match && match[1]) {
      return `https://lh3.googleusercontent.com/d/${match[1]}`;
    }
  }
  return url;
};

const UsersTable = ({ users, editingUserId, editDraft, setEditDraft, onViewDetails, onStartEdit, onSaveEdit, onCancelEdit, onToggleActive, onToggleComplianceAccess, onSendPasswordLink, onDeleteUser }) => (
  <div className="rounded-xl border border-slate-200 bg-white overflow-x-auto">
    <table className="w-full text-sm min-w-[880px]">
      <thead className="bg-slate-100 text-slate-600 text-xs uppercase">
        <tr>
          <th className="text-left px-4 py-3">Name</th>
          <th className="text-left px-4 py-3">Email</th>
          <th className="text-left px-4 py-3">Role</th>
          <th className="text-left px-4 py-3">Ticket Queues</th>
          <th className="text-left px-4 py-3">Status</th>
          <th className="text-left px-4 py-3">Actions</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-100">
        {!users.length && (
          <tr>
            <td colSpan={6} className="px-4 py-8 text-center text-sm text-slate-500">
              No users found for selected filters.
            </td>
          </tr>
        )}
        {users.map((user) => {
          const isEditing = editingUserId === user._id;
          const avatarUrl = formatImageUrl(user.profilePhoto || user.companyLogo);
          return (
            <tr key={user._id} className="hover:bg-slate-50/60 transition-colors">
              <td className="px-4 py-3">
                {isEditing ? (
                  <div className="space-y-1.5">
                    <input value={editDraft.name} onChange={(event) => setEditDraft((prev) => ({ ...prev, name: event.target.value }))} placeholder="Name" className="p-2 border rounded border-slate-300 text-sm w-full font-bold" />
                    <input value={editDraft.phone || ''} onChange={(event) => setEditDraft((prev) => ({ ...prev, phone: event.target.value }))} placeholder="Phone (+91...)" className="p-1.5 border rounded border-slate-300 text-xs w-full" />
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    {avatarUrl ? (
                      <img src={avatarUrl} alt={user.name} className="w-9 h-9 rounded-xl object-cover border border-slate-200 shrink-0" />
                    ) : (
                      <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-200 text-indigo-700 font-black text-xs flex items-center justify-center shrink-0">
                        {(user.name || 'U').charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="min-w-0">
                      <p className="font-bold text-slate-900 truncate flex items-center gap-1.5">
                        <span>{user.name}</span>
                        {user.companyName && (
                          <span className="text-[10px] font-semibold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">
                            {user.companyName}
                          </span>
                        )}
                      </p>
                      <p className="text-xs text-slate-500 font-medium">{user.phone || 'No phone'}</p>
                    </div>
                  </div>
                )}
              </td>
              <td className="px-4 py-3">
                {isEditing ? (
                  <input value={editDraft.email} onChange={(event) => setEditDraft((prev) => ({ ...prev, email: event.target.value }))} className="p-2 border rounded border-slate-300 text-sm w-full" />
                ) : (
                  <div>
                    <p className="text-slate-800 font-medium">{user.email}</p>
                    {user.authProvider === 'google' && (
                      <span className="inline-block mt-0.5 px-1.5 py-0.2 bg-red-50 text-red-600 border border-red-200 rounded text-[9px] font-bold">
                        Google Auth
                      </span>
                    )}
                  </div>
                )}
              </td>
              <td className="px-4 py-3">
                {isEditing ? (
                  <select value={editDraft.role} onChange={(event) => setEditDraft((prev) => ({ ...prev, role: event.target.value }))} className="p-2 border rounded border-slate-300 text-sm">
                    <option value="employee">employee</option>
                    <option value="client">client</option>
                    <option value="admin">admin</option>
                    <option value="partner">partner</option>
                  </select>
                ) : (
                  <div className="flex items-center gap-1.5">
                    <span className="font-semibold">{user.role}</span>
                    {user.canManageCompliance && (
                      <span className="px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-700 text-[10px] font-bold uppercase" title="Authorized Compliance Manager">
                        Compliance
                      </span>
                    )}
                  </div>
                )}
              </td>
              <td className="px-4 py-3">
                {isEditing && (editDraft.role === 'employee' || editDraft.role === 'admin') ? (
                  <div className="flex items-center gap-2">
                    {['Technical', 'Service', 'Support'].map((cat) => {
                      const isChecked = (editDraft.assignedTicketCategories || []).includes(cat);
                      return (
                        <label key={cat} className="inline-flex items-center gap-1 text-[11px] font-bold cursor-pointer">
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={(e) => {
                              const current = editDraft.assignedTicketCategories || [];
                              const updated = e.target.checked
                                ? [...current, cat]
                                : current.filter(c => c !== cat);
                              setEditDraft(prev => ({ ...prev, assignedTicketCategories: updated }));
                            }}
                            className="rounded border-slate-300 text-red-600 focus:ring-red-500"
                          />
                          {cat}
                        </label>
                      );
                    })}
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {user.role === 'admin' ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-slate-900 text-white">
                        All Queues (Admin)
                      </span>
                    ) : user.role === 'employee' ? (
                      user.assignedTicketCategories && user.assignedTicketCategories.length > 0 ? (
                        user.assignedTicketCategories.map(cat => (
                          <span key={cat} className={`px-2 py-0.5 rounded-full text-[10px] font-black border ${
                            cat === 'Technical' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                            cat === 'Service' ? 'bg-purple-50 text-purple-700 border-purple-200' :
                            'bg-amber-50 text-amber-800 border-amber-200'
                          }`}>
                            {cat}
                          </span>
                        ))
                      ) : (
                        <span className="text-[11px] text-slate-400 italic">No tickets assigned</span>
                      )
                    ) : (
                      <span className="text-[11px] text-slate-400">-</span>
                    )}
                  </div>
                )}
              </td>
              <td className="px-4 py-3">
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${user.isActive ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'}`}>
                  {user.isActive ? 'Active' : 'Inactive'}
                </span>
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1.5">
                  {isEditing ? (
                    <>
                      <button onClick={() => onSaveEdit(user)} className="px-2 py-1 rounded bg-indigo-600 text-white text-xs font-semibold">Save</button>
                      <button onClick={onCancelEdit} className="px-2 py-1 rounded bg-slate-200 text-slate-700 text-xs font-semibold">Cancel</button>
                    </>
                  ) : (
                    <>
                      {onViewDetails && (
                        <button onClick={() => onViewDetails(user)} className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold inline-flex items-center gap-1" title="View Full Details">
                          View
                        </button>
                      )}
                      <button onClick={() => onStartEdit(user)} className="px-2 py-1 rounded bg-indigo-100 text-indigo-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Pencil size={12} /> Edit
                      </button>
                      {onToggleComplianceAccess && user.role === 'employee' && (
                        <button 
                          onClick={() => onToggleComplianceAccess(user)} 
                          className={`px-2 py-1 rounded text-xs font-semibold inline-flex items-center gap-1 ${user.canManageCompliance ? 'bg-purple-100 text-purple-700 border border-purple-200' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}
                          title={user.canManageCompliance ? 'Revoke Compliance Authorization' : 'Grant Compliance Authorization'}
                        >
                          <ShieldCheck size={12} /> {user.canManageCompliance ? 'Compliance Authorized' : '+ Compliance'}
                        </button>
                      )}
                      <button onClick={() => onToggleActive(user)} className="px-2 py-1 rounded bg-amber-100 text-amber-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Power size={12} /> {user.isActive ? 'Deactivate' : 'Activate'}
                      </button>
                      <button onClick={() => onSendPasswordLink(user)} className="px-2 py-1 rounded bg-sky-100 text-sky-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Send size={12} /> Password Link
                      </button>
                      <button onClick={() => onDeleteUser(user)} className="px-2 py-1 rounded bg-rose-100 text-rose-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Trash2 size={12} /> Delete
                      </button>
                    </>
                  )}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

export default UsersTable;
