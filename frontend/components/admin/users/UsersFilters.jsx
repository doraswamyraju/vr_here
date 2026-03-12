import React from 'react';
import { Search } from 'lucide-react';

const UsersFilters = ({
  roleFilter,
  setRoleFilter,
  searchText,
  setSearchText,
  totalUsers,
  filteredCount
}) => (
  <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
    <div className="flex flex-col sm:flex-row gap-3">
      <div className="relative flex-1">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          value={searchText}
          onChange={(event) => setSearchText(event.target.value)}
          placeholder="Search by name, email, phone"
          className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-lg text-sm bg-white"
        />
      </div>
      <select
        value={roleFilter}
        onChange={(event) => setRoleFilter(event.target.value)}
        className="sm:w-48 p-2 border border-slate-300 rounded-lg text-sm bg-white"
      >
        <option value="all">All Roles</option>
        <option value="admin">Admin</option>
        <option value="employee">Employee</option>
        <option value="client">Client</option>
      </select>
    </div>
    <p className="text-xs text-slate-500">
      Showing {filteredCount} of {totalUsers} users
    </p>
  </div>
);

export default UsersFilters;
