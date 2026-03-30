import React, { useState } from 'react';
import { Plus, ShoppingBag, CheckSquare, X } from 'lucide-react';

const QuickActionFAB = ({ onNewOrder, onNewTodo }) => {
  const [isOpen, setIsOpen] = useState(false);

  const actions = [
    {
      label: 'New Order',
      icon: ShoppingBag,
      onClick: () => {
        onNewOrder();
        setIsOpen(false);
      },
      color: 'bg-emerald-600'
    },
    {
      label: 'New Task',
      icon: CheckSquare,
      onClick: () => {
        onNewTodo();
        setIsOpen(false);
      },
      color: 'bg-blue-600'
    }
  ];

  return (
    <div className="fixed bottom-8 right-8 z-[100] flex flex-col items-end gap-4 overflow-visible">
      {/* Action Menu */}
      {isOpen && (
        <div className="flex flex-col items-end gap-3 mb-2 animate-in slide-in-from-bottom-5 duration-200">
          {actions.map((action, idx) => (
            <button
              key={idx}
              onClick={action.onClick}
              className="flex items-center gap-3 group"
            >
              <span className="bg-slate-900/80 backdrop-blur-sm text-white text-xs font-bold px-3 py-1.5 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity shadow-lg">
                {action.label}
              </span>
              <div className={`${action.color} text-white p-3 rounded-full shadow-xl hover:scale-110 transition-transform active:scale-95`}>
                <action.icon size={20} />
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Main Toggle Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`${isOpen ? 'bg-slate-800 rotate-45' : 'bg-indigo-600'} text-white p-4 rounded-full shadow-2xl transition-all duration-300 hover:scale-110 active:scale-95 flex items-center justify-center`}
      >
        <Plus size={28} />
      </button>
    </div>
  );
};

export default QuickActionFAB;
