import React, { useMemo, useState } from 'react';
import axios from 'axios';
import { Users as UsersIcon, Mail } from 'lucide-react';
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

  const config = useMemo(() => ({ headers: { Authorization: `Bearer ${token}` } }), [token]);

  const employeeUsers = useMemo(() => users.filter((item) => item.role === 'employee'), [users]);
  const filteredUsers = useMemo(() => {
    const normalizedSearch = searchText.trim().toLowerCase();

    return users.filter((item) => {
      const roleMatches = roleFilter === 'all' || item.role === roleFilter;
      if (!roleMatches) return false;
      if (!normalizedSearch) return true;

      const haystack = [item.name, item.email, item.phone, item.role]
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
    </div>
  );
};

export default UsersModule;
