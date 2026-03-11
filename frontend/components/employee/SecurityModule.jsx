import React from 'react';

const SecurityModule = () => {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6">
      <h3 className="font-bold text-slate-800 mb-4">Security & Access Rules</h3>
      <div className="space-y-3 text-sm text-slate-600">
        <p>1. Employee sees only assigned orders and task-level assignments.</p>
        <p>2. Admin-only operations (commercial edits, full assignment controls) remain restricted.</p>
        <p>3. All status/task/document updates should be logged for audit.</p>
        <p>4. Token/session checks are enforced before loading this dashboard.</p>
      </div>
      <p className="text-xs text-indigo-600 mt-4">Placeholder ready for audit timeline and role-permission matrix module.</p>
    </div>
  );
};

export default SecurityModule;

