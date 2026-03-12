import React from 'react';
import { USER_ROLES } from './constants';

const AddUserForm = ({ draft, setDraft, onCreateUser, isCreating }) => (
  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
    <p className="font-semibold text-slate-800">Add User</p>
    <p className="text-xs text-slate-500 mb-3">A password setup email will be sent automatically.</p>
    <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
      <input value={draft.name} onChange={(event) => setDraft((prev) => ({ ...prev, name: event.target.value }))} placeholder="Name" className="p-2 border rounded-lg border-slate-300 bg-white text-sm" />
      <input value={draft.email} onChange={(event) => setDraft((prev) => ({ ...prev, email: event.target.value }))} placeholder="Email" className="p-2 border rounded-lg border-slate-300 bg-white text-sm" />
      <input value={draft.phone} onChange={(event) => setDraft((prev) => ({ ...prev, phone: event.target.value }))} placeholder="Phone" className="p-2 border rounded-lg border-slate-300 bg-white text-sm" />
      <select value={draft.role} onChange={(event) => setDraft((prev) => ({ ...prev, role: event.target.value }))} className="p-2 border rounded-lg border-slate-300 bg-white text-sm">
        {USER_ROLES.map((role) => (
          <option key={role} value={role}>{role}</option>
        ))}
      </select>
    </div>
    <button onClick={onCreateUser} disabled={isCreating} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold disabled:opacity-50">
      {isCreating ? 'Creating...' : 'Create User & Send Password Link'}
    </button>
  </div>
);

export default AddUserForm;
