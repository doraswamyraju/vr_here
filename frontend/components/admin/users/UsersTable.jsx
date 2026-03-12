import React from 'react';
import { Pencil, Power, Send } from 'lucide-react';

const UsersTable = ({ users, editingUserId, editDraft, setEditDraft, onStartEdit, onSaveEdit, onCancelEdit, onToggleActive, onSendPasswordLink }) => (
  <div className="rounded-xl border border-slate-200 bg-white overflow-x-auto">
    <table className="w-full text-sm min-w-[880px]">
      <thead className="bg-slate-100 text-slate-600 text-xs uppercase">
        <tr>
          <th className="text-left px-4 py-3">Name</th>
          <th className="text-left px-4 py-3">Email</th>
          <th className="text-left px-4 py-3">Role</th>
          <th className="text-left px-4 py-3">Status</th>
          <th className="text-left px-4 py-3">Actions</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-100">
        {!users.length && (
          <tr>
            <td colSpan={5} className="px-4 py-8 text-center text-sm text-slate-500">
              No users found for selected filters.
            </td>
          </tr>
        )}
        {users.map((user) => {
          const isEditing = editingUserId === user._id;
          return (
            <tr key={user._id}>
              <td className="px-4 py-3">
                {isEditing ? (
                  <input value={editDraft.name} onChange={(event) => setEditDraft((prev) => ({ ...prev, name: event.target.value }))} className="p-2 border rounded border-slate-300 text-sm w-full" />
                ) : user.name}
              </td>
              <td className="px-4 py-3">
                {isEditing ? (
                  <input value={editDraft.email} onChange={(event) => setEditDraft((prev) => ({ ...prev, email: event.target.value }))} className="p-2 border rounded border-slate-300 text-sm w-full" />
                ) : user.email}
              </td>
              <td className="px-4 py-3">
                {isEditing ? (
                  <select value={editDraft.role} onChange={(event) => setEditDraft((prev) => ({ ...prev, role: event.target.value }))} className="p-2 border rounded border-slate-300 text-sm">
                    <option value="employee">employee</option>
                    <option value="client">client</option>
                    <option value="admin">admin</option>
                  </select>
                ) : user.role}
              </td>
              <td className="px-4 py-3">
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${user.isActive ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'}`}>
                  {user.isActive ? 'Active' : 'Inactive'}
                </span>
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  {isEditing ? (
                    <>
                      <button onClick={() => onSaveEdit(user)} className="px-2 py-1 rounded bg-indigo-600 text-white text-xs font-semibold">Save</button>
                      <button onClick={onCancelEdit} className="px-2 py-1 rounded bg-slate-200 text-slate-700 text-xs font-semibold">Cancel</button>
                    </>
                  ) : (
                    <>
                      <button onClick={() => onStartEdit(user)} className="px-2 py-1 rounded bg-indigo-100 text-indigo-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Pencil size={12} /> Edit
                      </button>
                      <button onClick={() => onToggleActive(user)} className="px-2 py-1 rounded bg-amber-100 text-amber-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Power size={12} /> {user.isActive ? 'Deactivate' : 'Activate'}
                      </button>
                      <button onClick={() => onSendPasswordLink(user)} className="px-2 py-1 rounded bg-sky-100 text-sky-700 text-xs font-semibold inline-flex items-center gap-1">
                        <Send size={12} /> Password Link
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
