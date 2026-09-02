import React, { useMemo, useState } from 'react';
import axios from 'axios';
import {
  Users as UsersIcon,
  Mail,
  X,
  Phone,
  Building2,
  MapPin,
  FileText,
  ShieldCheck,
  Calendar,
  User as UserIcon,
  Image as ImageIcon
} from 'lucide-react';
import AddUserForm from './AddUserForm';
import UsersFilters from './UsersFilters';
import UsersTable from './UsersTable';
import WorkloadPanel from './WorkloadPanel';
import AssignmentPreview from './AssignmentPreview';
import WebmailModule from './WebmailModule';

const UsersModule = ({ token, users, orders, onRefresh }) => {
  const [createDraft, setCreateDraft] = useState({ name: '', email: '', phone: '', role: 'employee', assignedTicketCategories: [] });
  const [isCreating, setIsCreating] = useState(false);
  const [editingUserId, setEditingUserId] = useState('');
  const [editDraft, setEditDraft] = useState({ name: '', email: '', role: 'employee', phone: '', assignedTicketCategories: [] });
  const [selectedEmployeeId, setSelectedEmployeeId] = useState('');
  const [attendanceSummary, setAttendanceSummary] = useState({ items: [] });
  const [roleFilter, setRoleFilter] = useState('all');
  const [searchText, setSearchText] = useState('');
  const [subTab, setSubTab] = useState('app-users'); // 'app-users' or 'webmail'
  const [viewingUser, setViewingUser] = useState(null);

  const config = useMemo(() => ({ headers: { Authorization: `Bearer ${token}` } }), [token]);

  const employeeUsers = useMemo(() => users.filter((item) => item.role === 'employee'), [users]);
  const filteredUsers = useMemo(() => {
    const normalizedSearch = searchText.trim().toLowerCase();

    return users.filter((item) => {
      const roleMatches = roleFilter === 'all' || item.role === roleFilter;
      if (!roleMatches) return false;
      if (!normalizedSearch) return true;

      const haystack = [item.name, item.email, item.phone, item.role, item.companyName, item.gstin]
        .map((value) => String(value || '').toLowerCase())
        .join(' ');

      return haystack.includes(normalizedSearch);
    });
  }, [users, roleFilter, searchText]);

  const loadSummary = async () => {
    const { data } = await axios.get('/api/attendance/admin/summary', config);
    setAttendanceSummary(data || { items: [] });
  };

  const createUser = async () => {
    if (!createDraft.name || !createDraft.email) return;
    setIsCreating(true);
    try {
      await axios.post('/api/auth/users', createDraft, config);
      setCreateDraft({ name: '', email: '', phone: '', role: 'employee', assignedTicketCategories: [] });
      await onRefresh();
      await loadSummary();
      alert('User created and password setup email sent.');
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to create user');
    } finally {
      setIsCreating(false);
    }
  };

  const startEdit = (user) => {
    setEditingUserId(user._id);
    setEditDraft({
      name: user.name || '',
      email: user.email || '',
      role: user.role || 'employee',
      phone: user.phone || '',
      assignedTicketCategories: user.assignedTicketCategories || []
    });
  };

  const saveEdit = async (user) => {
    await axios.put(`/api/auth/users/${user._id}`, editDraft, config);
    setEditingUserId('');
    await onRefresh();
    await loadSummary();
  };

  const toggleActive = async (user) => {
    await axios.patch(`/api/auth/users/${user._id}/toggle-active`, {}, config);
    await onRefresh();
    await loadSummary();
  };

  const toggleComplianceAccess = async (user) => {
    await axios.put(`/api/auth/users/${user._id}`, { canManageCompliance: !user.canManageCompliance }, config);
    await onRefresh();
  };

  const sendPasswordLink = async (user) => {
    await axios.post(`/api/auth/users/${user._id}/send-password-link`, {}, config);
    alert(`Password link sent to ${user.email}`);
  };

  const deleteUser = async (user) => {
    if (!window.confirm(`Are you sure you want to PERMANENTLY DELETE user ${user.name}? This cannot be undone.`)) return;
    try {
      await axios.delete(`/api/auth/users/${user._id}`, config);
      await onRefresh();
      await loadSummary();
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to delete user');
    }
  };

  React.useEffect(() => {
    loadSummary().catch(() => setAttendanceSummary({ items: [] }));
  }, []);

  return (
    <div className="space-y-6">
      {/* Tabbed Navigation Bar */}
      <div className="flex border-b border-slate-200 bg-white px-4 rounded-xl shadow-[0_2px_10px_rgba(0,0,0,0.02)]">
        <button
          onClick={() => setSubTab('app-users')}
          className={`flex items-center gap-2 px-5 py-3.5 text-sm font-bold border-b-2 transition-all duration-200 ${
            subTab === 'app-users'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800 hover:border-slate-300'
          }`}
        >
          <UsersIcon size={16} />
          App Users ({users.length})
        </button>
        <button
          onClick={() => setSubTab('webmail')}
          className={`flex items-center gap-2 px-5 py-3.5 text-sm font-bold border-b-2 transition-all duration-200 ${
            subTab === 'webmail'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800 hover:border-slate-300'
          }`}
        >
          <Mail size={16} />
          Webmail Accounts
        </button>
      </div>

      {subTab === 'app-users' ? (
        <div className="space-y-4">
          <AddUserForm draft={createDraft} setDraft={setCreateDraft} onCreateUser={createUser} isCreating={isCreating} />
          <UsersFilters
            roleFilter={roleFilter}
            setRoleFilter={setRoleFilter}
            searchText={searchText}
            setSearchText={setSearchText}
            totalUsers={users.length}
            filteredCount={filteredUsers.length}
          />

          <UsersTable
            users={filteredUsers}
            editingUserId={editingUserId}
            editDraft={editDraft}
            setEditDraft={setEditDraft}
            onViewDetails={(user) => setViewingUser(user)}
            onStartEdit={startEdit}
            onSaveEdit={saveEdit}
            onCancelEdit={() => setEditingUserId('')}
            onToggleActive={toggleActive}
            onToggleComplianceAccess={toggleComplianceAccess}
            onSendPasswordLink={sendPasswordLink}
            onDeleteUser={deleteUser}
          />

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <WorkloadPanel attendanceSummary={attendanceSummary} />
            <div className="space-y-3">
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <p className="font-semibold text-slate-800">Select Employee</p>
                <select value={selectedEmployeeId} onChange={(event) => setSelectedEmployeeId(event.target.value)} className="mt-2 w-full p-2 border rounded-lg border-slate-300 bg-white text-sm">
                  <option value="">Select</option>
                  {employeeUsers.map((employee) => (
                    <option key={employee._id} value={employee._id}>{employee.name}</option>
                  ))}
                </select>
              </div>
              <AssignmentPreview employeeId={selectedEmployeeId} orders={orders} />
            </div>
          </div>
        </div>
      ) : (
        <WebmailModule token={token} />
      )}

      {/* --- USER FULL DETAILS MODAL --- */}
      {viewingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-white rounded-3xl max-w-2xl w-full shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-200">
            {/* Header with gradient */}
            <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 p-6 text-white flex items-start justify-between">
              <div className="flex items-center gap-4">
                {viewingUser.profilePhoto ? (
                  <img src={viewingUser.profilePhoto} alt={viewingUser.name} className="w-16 h-16 rounded-2xl object-cover border-2 border-indigo-400 shadow-md" />
                ) : viewingUser.companyLogo ? (
                  <img src={viewingUser.companyLogo} alt={viewingUser.name} className="w-16 h-16 rounded-2xl object-contain bg-white/10 border-2 border-indigo-400 p-1 shadow-md" />
                ) : (
                  <div className="w-16 h-16 rounded-2xl bg-indigo-600 flex items-center justify-center font-black text-2xl shadow-md">
                    {(viewingUser.name || 'U').charAt(0).toUpperCase()}
                  </div>
                )}
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-xl font-black text-white">{viewingUser.name}</h3>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider ${viewingUser.isActive ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'}`}>
                      {viewingUser.isActive ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 flex items-center gap-2">
                    <span>{viewingUser.email}</span>
                    {viewingUser.phone && <span>• {viewingUser.phone}</span>}
                  </p>
                  <span className="inline-block mt-2 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-white/10 text-slate-200 uppercase tracking-widest border border-white/20">
                    Role: {viewingUser.role}
                  </span>
                </div>
              </div>

              <button onClick={() => setViewingUser(null)} className="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-white/10 transition-colors">
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
              
              {/* Media Visuals */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80 flex items-center gap-3">
                  {viewingUser.profilePhoto ? (
                    <img src={viewingUser.profilePhoto} alt="Personal" className="w-12 h-12 rounded-full object-cover border" />
                  ) : (
                    <div className="w-12 h-12 rounded-full bg-slate-200 flex items-center justify-center text-slate-400">
                      <UserIcon size={20} />
                    </div>
                  )}
                  <div>
                    <p className="text-[10px] font-bold text-slate-400 uppercase">Person Photo</p>
                    <p className="text-xs font-bold text-slate-700">{viewingUser.profilePhoto ? 'Uploaded' : 'Not set'}</p>
                  </div>
                </div>

                <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80 flex items-center gap-3">
                  {viewingUser.companyLogo ? (
                    <img src={viewingUser.companyLogo} alt="Logo" className="w-12 h-12 rounded-xl object-contain bg-white border p-1" />
                  ) : (
                    <div className="w-12 h-12 rounded-xl bg-slate-200 flex items-center justify-center text-slate-400">
                      <ImageIcon size={20} />
                    </div>
                  )}
                  <div>
                    <p className="text-[10px] font-bold text-slate-400 uppercase">Company Logo</p>
                    <p className="text-xs font-bold text-slate-700">{viewingUser.companyLogo ? 'Uploaded' : 'Not set'}</p>
                  </div>
                </div>
              </div>

              {/* Business & Account Information */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-slate-50/50 p-4 rounded-2xl border border-slate-200/60 text-xs">
                <div>
                  <p className="text-slate-400 font-bold uppercase text-[10px]">Company / Business Name</p>
                  <p className="text-slate-800 font-bold mt-0.5">{viewingUser.companyName || 'Not specified'}</p>
                </div>
                <div>
                  <p className="text-slate-400 font-bold uppercase text-[10px]">Entity Type</p>
                  <p className="text-slate-800 font-bold mt-0.5">{viewingUser.businessType || 'Not specified'}</p>
                </div>
                <div>
                  <p className="text-slate-400 font-bold uppercase text-[10px]">GSTIN</p>
                  <p className="text-slate-800 font-bold mt-0.5">{viewingUser.gstin || 'Not provided'}</p>
                </div>
                <div>
                  <p className="text-slate-400 font-bold uppercase text-[10px]">PAN Card / Number</p>
                  <p className="text-slate-800 font-bold mt-0.5">{viewingUser.panNumber || viewingUser.panCard || 'Not provided'}</p>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-slate-400 font-bold uppercase text-[10px]">Registered Business Address</p>
                  <p className="text-slate-800 font-medium mt-0.5">{viewingUser.address || 'No address provided'}</p>
                </div>
                <div>
                  <p className="text-slate-400 font-bold uppercase text-[10px]">Auth Provider</p>
                  <p className="text-slate-800 font-bold mt-0.5">{viewingUser.authProvider === 'google' ? 'Google OAuth' : 'Standard Email & Password'}</p>
                </div>
                <div>
                  <p className="text-slate-400 font-bold uppercase text-[10px]">Account Registered On</p>
                  <p className="text-slate-800 font-bold mt-0.5">{viewingUser.createdAt ? new Date(viewingUser.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'N/A'}</p>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 bg-slate-50 border-t border-slate-100 flex justify-end">
              <button
                onClick={() => setViewingUser(null)}
                className="px-6 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UsersModule;
