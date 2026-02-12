import React, { useState } from 'react';
import {
  LayoutDashboard, Users, FileText, CheckSquare, Shield, Settings, Bell, Search,
  Menu, ChevronDown, MoreVertical, ArrowUpRight, ArrowDownRight, Clock, CheckCircle2,
  AlertCircle, Briefcase, LogOut, Plus, Eye, EyeOff, Download, Trash2, Building2,
  User, CreditCard, MapPin, Phone, Mail, Calendar, ChevronRight, X, Kanban, List,
  ArrowRight, PieChart, ChevronLeft, Layers, FileInput, MessageSquare, Anchor,
  Globe, Factory, Stamp, HardHat, DollarSign, FolderOpen, BookOpen, Truck, BarChart,
  ChevronDown as ChevronDownIcon, ChevronRight as ChevronRightIcon, Landmark, Scale,
  Receipt, FileSpreadsheet, Percent, Database, UserCheck, Briefcase as ServiceIcon,
  MessageCircle, FileCheck
} from 'lucide-react';
import { PieChart as RechartsPie, Pie, Cell, Tooltip, ResponsiveContainer, BarChart as RechartsBarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

// --- SERVICE CATALOG (From VR Here Services.docx) ---
const SERVICE_CATALOG = {
  'Machinery & Industrial': ['Machinery Sourcing', 'Vendor Verification', 'Turnkey Setup', 'Feasibility Analysis'],
  'Certification (ISO)': ['ISO 9001 (QMS)', 'ISO 14001 (EMS)', 'ISO 45001 (OHS)', 'ISO 27001 (ISMS)', 'HACCP/GMP', 'CE Marking'],
  'Accounting & Tax': ['Cloud Accounting', 'GST Returns', 'Income Tax Filing', 'TDS Filing', 'Statutory Audit', 'Tax Audit (3CD)', 'Internal Audit'],
  'Business Registration': ['Pvt Ltd Incorporation', 'LLP Registration', 'Partnership Firm', 'Section 8 (NGO)', 'Udyam (MSME)', 'Import Export Code'],
  'Licensing & Compliance': ['FSSAI License', 'Trade License', 'Labour License', 'Factory License', 'Pollution Control (PCB)', 'ROC Filings'],
  'Govt Portals': ['GeM Registration', 'TReDS Registration', 'RERA Registration', 'AP/TS Single Window'],
  'Consultancy & Finance': ['DPR Preparation', 'CMA Data', 'Term Loan / Working Capital', 'Mudra Loans', 'Subsidy Guidance'],
  'Startup Support': ['Business Plan', 'Pitch Decks', 'Trademark & IP', 'Digital Signatures (DSC)']
};

const BRANCHES = ['Ravulapalem (Head Office)', 'Atreyapuram', 'Amalapuram', 'Versatile'];

// --- CHECKLIST TEMPLATES (New Feature) ---
const CHECKLIST_TEMPLATES = {
  'Pvt Ltd Incorporation': [
    'Collect KYC Documents (PAN, Aadhaar)',
    'Apply for DSC (Digital Signature)',
    'Name Reservation (RUN)',
    'Draft MOA & AOA',
    'File SPICe+ Form',
    'PAN & TAN Allotment',
    'Upload Final Certificate'
  ],
  'GST Registration': [
    'Collect Business Details',
    'Prepare Rent Agreement/NOC',
    'File GST REG-01',
    'Respond to Clarifications (if any)',
    'Final Certificate Download'
  ]
};

const EMPLOYEES = [
  { id: 1, name: 'Rahul Sharma', role: 'Maker' },
  { id: 2, name: 'Priya Verma', role: 'Maker' },
  { id: 3, name: 'Suresh Kumar', role: 'Checker' },
  { id: 4, name: 'Amit Patel', role: 'Checker' }
];

// --- MOCK DATA ---

// Projects
const INITIAL_PROJECTS = [
  { id: 1, title: 'Statutory Audit FY 2024-25', client: 'TechFlow Solutions', progress: 45, budget: 150000, billed: 75000, received: 25000, status: 'In Progress', type: 'Audit' },
  { id: 2, title: 'Pvt Ltd Incorporation', client: 'Green Earth NGO', progress: 80, budget: 25000, billed: 15000, received: 15000, status: 'Review', type: 'Registration' },
  { id: 3, title: 'DPR for Food Processing Unit', client: 'Apex Foods', progress: 10, budget: 120000, billed: 0, received: 0, status: 'In Progress', type: 'Consultancy' },
];

// WBS
const INITIAL_WBS = [
  {
    id: '1', sNo: '1', name: 'Planning & Risk Assessment', duration: '', start: '01 Apr 24', end: '10 Apr 24', progress: '100%', plannedStart: '-', plannedEnd: '-', dep: '', type: 'parent', expanded: true,
    children: [
      { id: '1-1', sNo: '', name: 'Engagement Letter Signing', duration: '1 day', start: '01 Apr 24', end: '01 Apr 24', progress: '100%', plannedStart: '01 Apr 24', plannedEnd: '01 Apr 24', dep: '-', type: 'child', assignee: 'Suresh (Partner)' },
      { id: '1-2', sNo: '', name: 'Internal Control Review', duration: '5 days', start: '02 Apr 24', end: '07 Apr 24', progress: '100%', plannedStart: '02 Apr 24', plannedEnd: '07 Apr 24', dep: '1-1', type: 'child', assignee: 'Rahul (Senior)' },
    ]
  },
  {
    id: '2', sNo: '2', name: 'Execution (Vouching & Verification)', duration: '', start: '11 Apr 24', end: '30 Apr 24', progress: '40%', plannedStart: '-', plannedEnd: '-', dep: '', type: 'parent', expanded: true,
    children: [
      { id: '2-1', sNo: '', name: 'Sales & Revenue Vouching', duration: '5 days', start: '11 Apr 24', end: '16 Apr 24', progress: '100%', plannedStart: '-', plannedEnd: '-', dep: '1-2', type: 'child', assignee: 'Arjun (Article)' },
      { id: '2-2', sNo: '', name: 'Purchase & Expense Vouching', duration: '7 days', start: '17 Apr 24', end: '24 Apr 24', progress: '20%', plannedStart: '-', plannedEnd: '-', dep: '2-1', type: 'child', assignee: 'Priya (Article)' },
      { id: '2-3', sNo: '', name: 'Fixed Asset Verification', duration: '3 days', start: '25 Apr 24', end: '28 Apr 24', progress: '0%', plannedStart: '-', plannedEnd: '-', dep: '2-2', type: 'child', assignee: 'Rahul (Senior)' },
    ]
  },
];

const INITIAL_PAYMENTS = [
  { id: 1, date: '2024-04-01', type: 'Retainer Advance', mode: 'NEFT', amount: 25000, status: 'Received' },
  { id: 2, date: '2024-05-15', type: 'Interim Billing', mode: 'Cheque', amount: 50000, status: 'Pending' },
];

const INITIAL_FEES = [
  { id: 1, item: 'Statutory Audit Fees', qty: 1, rate: 100000, amount: 100000 },
  { id: 2, item: 'Tax Audit Filing (3CD)', qty: 1, rate: 35000, amount: 35000 },
  { id: 3, item: 'ROC Filing Charges (Actuals)', qty: 1, rate: 5000, amount: 5000 },
  { id: 4, item: 'Out of Pocket Expenses', qty: 1, rate: 10000, amount: 10000 },
];

// To Do List
const INITIAL_TODO = [
  { id: 1, task: 'File GSTR-1 for TechFlow', due: 'Today', priority: 'High', assignee: 'Arjun' },
  { id: 2, task: 'Renew DSC for Director (Green Earth)', due: 'Tomorrow', priority: 'Medium', assignee: 'Priya' },
  { id: 3, task: 'Prepare Minutes for AGM (Apex)', due: 'Next Week', priority: 'Low', assignee: 'Rahul' },
];

// Quotations
const INITIAL_QUOTES = [
  { id: 'QT-2024-001', client: 'New Horizon Ventures', subject: 'Company Incorporation & Trademark', amount: 45000, status: 'Sent' },
  { id: 'QT-2024-002', client: 'Delta Exports', subject: 'IEC Registration & GeM Listing', amount: 15000, status: 'Draft' },
];

// Finance (Invoices)
const INITIAL_INVOICES = [
  { id: 'INV-24-101', client: 'TechFlow Solutions', date: '01 Apr 2024', amount: 25000, status: 'Paid' },
  { id: 'INV-24-102', client: 'Green Earth NGO', date: '15 Apr 2024', amount: 15000, status: 'Overdue' },
];

// Payroll
const INITIAL_PAYROLL = [
  { id: 1, name: 'Rahul Sharma', role: 'Senior Audit Asst', days: 22, salary: 25000, status: 'Processed' },
  { id: 2, name: 'Arjun K', role: 'Article Asst', days: 20, salary: 8000, status: 'Pending' },
];

// Library (Parties)
const INITIAL_PARTIES = [
  { id: 1, name: 'TechFlow Solutions', type: 'Client (Pvt Ltd)', contact: '9876543210' },
  { id: 2, name: 'Green Earth NGO', type: 'Client (Trust)', contact: '8877665544' },
  { id: 3, name: 'Office Supplies Co.', type: 'Vendor', contact: '7766554433' },
];

// Service Requests (New)
const INITIAL_SERVICE_REQUESTS = [
  { id: 1, client: 'New Horizon Ventures', service: 'ISO 9001 Certification', date: '2024-10-15', status: 'New', assignedTo: '-' },
  { id: 2, client: 'Delta Exports', service: 'GST Registration', date: '2024-10-14', status: 'Assigned', assignedTo: 'Rahul (Senior)' },
  { id: 3, client: 'Apex Foods', service: 'FSSAI License Renewal', date: '2024-10-12', status: 'In Progress', assignedTo: 'Priya (Article)' },
];

// Reports Data (Demo)
const INITIAL_REPORTS = [
  { id: 1, name: 'GST Filing Status Report - Oct 2024', type: 'Compliance', generated: '10 Oct 2024' },
  { id: 2, name: 'Pending TDS Returns (Q2)', type: 'Taxation', generated: '05 Oct 2024' },
  { id: 3, name: 'Employee Utilization - Sep 2024', type: 'Internal', generated: '01 Oct 2024' },
  { id: 4, name: 'Client Fee Outstanding', type: 'Finance', generated: 'Weekly' },
];


// --- COMPONENTS ---

const StatusBadge = ({ status }) => {
  const styles = {
    'In Progress': 'bg-blue-50 text-blue-700',
    'Completed': 'bg-emerald-50 text-emerald-700',
    'Paid': 'bg-emerald-50 text-emerald-700',
    'Received': 'bg-emerald-50 text-emerald-700',
    'Processed': 'bg-emerald-50 text-emerald-700',
    'Sent': 'bg-blue-50 text-blue-700',
    'Overdue': 'bg-rose-50 text-rose-700',
    'Pending': 'bg-amber-50 text-amber-700',
    'Review': 'bg-purple-50 text-purple-700',
    'Draft': 'bg-slate-100 text-slate-600',
    'New': 'bg-indigo-100 text-indigo-700',
    'Assigned': 'bg-cyan-100 text-cyan-700'
  };
  return <span className={`px-2 py-1 rounded text-xs font-bold ${styles[status] || 'bg-slate-100'}`}>{status}</span>;
};

const SidebarItem = ({ icon: Icon, label, active, onClick, collapsed }) => (
  <button onClick={onClick} className={`flex items-center w-full p-3 mb-1 rounded-xl transition-all duration-200 group relative ${active ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-200' : 'text-slate-500 hover:bg-slate-50 hover:text-indigo-600'}`} title={collapsed ? label : ''}>
    <Icon size={20} className="shrink-0" />
    <span className={`ml-3 font-medium text-sm whitespace-nowrap transition-all duration-300 ${collapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100 w-auto'}`}>{label}</span>
  </button>
);

// 1. PROJECT WIZARD (Updated for Checklist & Maker-Checker)
const ProjectWizard = ({ onClose, onSave }) => {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    title: '', client: '', service: 'Pvt Ltd Incorporation',
    maker: '', checker: '', checklist: CHECKLIST_TEMPLATES['Pvt Ltd Incorporation']
  });

  const handleServiceChange = (e) => {
    const service = e.target.value;
    setFormData({
      ...formData,
      service,
      checklist: CHECKLIST_TEMPLATES[service] || []
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white w-[900px] h-[650px] rounded-3xl shadow-2xl flex overflow-hidden animate-in zoom-in-95 duration-300">
        <div className="w-1/3 bg-slate-900 p-8 flex flex-col justify-between text-white relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-600 rounded-full blur-3xl -mr-16 -mt-16 opacity-50"></div>
          <div><h2 className="text-3xl font-bold mb-2">New Engagement</h2><p className="text-slate-400">Set up a new client mandate.</p></div>
          <div className="space-y-6 relative z-10">
            {[1, 2, 3].map(i => (
              <div key={i} className={`flex items-center gap-4 ${step === i ? 'opacity-100' : 'opacity-40'}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold border-2 ${step === i ? 'bg-indigo-500 border-indigo-500 text-white' : 'border-slate-600 text-slate-400'}`}>{i}</div>
                <div><p className="font-bold text-sm">{i === 1 ? 'Details & Service' : i === 2 ? 'Team & Tasks' : ' commercials'}</p><p className="text-xs text-slate-400">{i === 1 ? 'Client Info' : i === 2 ? 'Maker-Checker' : 'Fees'}</p></div>
              </div>
            ))}
          </div>
        </div>

        <div className="flex-1 p-10 flex flex-col bg-slate-50">
          <div className="flex-1 overflow-y-auto pr-2">
            {step === 1 && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                <h3 className="text-xl font-bold text-slate-800">Engagement Basics</h3>
                <div className="grid grid-cols-2 gap-5">
                  <div className="col-span-2"><label className="text-xs font-bold text-slate-500 uppercase">Engagement Title</label><input className="w-full p-3 border border-slate-200 rounded-xl bg-white focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="e.g. Statutory Audit FY 2024-25" /></div>
                  <div><label className="text-xs font-bold text-slate-500 uppercase">Client</label><input className="w-full p-3 border border-slate-200 rounded-xl bg-white" placeholder="Search Client..." /></div>
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase">Service Type</label>
                    <select className="w-full p-3 border border-slate-200 rounded-xl bg-white" value={formData.service} onChange={handleServiceChange}>
                      <option value="Pvt Ltd Incorporation">Pvt Ltd Incorporation</option>
                      <option value="GST Registration">GST Registration</option>
                      <option value="ISO Certification">ISO Certification</option>
                    </select>
                  </div>
                  <div><label className="text-xs font-bold text-slate-500 uppercase">Start Date</label><input type="date" className="w-full p-3 border border-slate-200 rounded-xl bg-white" /></div>
                  <div><label className="text-xs font-bold text-slate-500 uppercase">Deadline (Due Date)</label><input type="date" className="w-full p-3 border border-slate-200 rounded-xl bg-white" /></div>
                </div>
              </div>
            )}

            {/* STEP 2: Team & Checklist (Updated) */}
            {step === 2 && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                <h3 className="text-xl font-bold text-slate-800">Team & Workflow</h3>

                <div className="grid grid-cols-2 gap-5">
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase">Assign Maker (Execution)</label>
                    <select className="w-full p-3 border border-slate-200 rounded-xl bg-white">
                      <option value="">Select Staff</option>
                      {EMPLOYEES.filter(e => e.role === 'Maker').map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase">Assign Checker (Review)</label>
                    <select className="w-full p-3 border border-slate-200 rounded-xl bg-white">
                      <option value="">Select Senior</option>
                      {EMPLOYEES.filter(e => e.role === 'Checker').map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
                    </select>
                  </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <h4 className="text-sm font-bold text-slate-700 mb-3 flex items-center"><CheckSquare size={16} className="mr-2" /> Task Checklist Preview</h4>
                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {formData.checklist && formData.checklist.length > 0 ? (
                      formData.checklist.map((task, i) => (
                        <div key={i} className="flex items-center text-sm text-slate-600 bg-slate-50 p-2 rounded">
                          <span className="w-5 h-5 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center text-xs font-bold mr-3">{i + 1}</span>
                          {task}
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-slate-400 italic">No checklist template available for this service.</p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {step === 3 && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                <h3 className="text-xl font-bold text-slate-800">Fee Structure (Scope)</h3>
                <div className="bg-indigo-50 border border-indigo-100 p-4 rounded-xl text-sm text-indigo-800 mb-4 flex items-start"><AlertCircle size={16} className="mr-2 mt-0.5 shrink-0" /><span>Standard professional fees applied. Adjust as needed.</span></div>
                <div className="space-y-3">
                  <div className="flex gap-2"><input className="flex-1 p-2 border rounded-lg bg-white" placeholder="Fee Description" /><input className="w-24 p-2 border rounded-lg bg-white" placeholder="Qty" /><input className="w-32 p-2 border rounded-lg bg-white" placeholder="Rate" /><button className="p-2 bg-indigo-600 text-white rounded-lg"><Plus size={18} /></button></div>
                  <div className="flex justify-between items-center p-3 bg-white border border-slate-100 rounded-lg"><span className="text-sm font-medium">Professional Fees</span><span className="font-bold">₹ 50,000</span></div>
                  <div className="flex justify-between items-center p-3 bg-white border border-slate-100 rounded-lg"><span className="text-sm font-medium">Filing Charges (Actuals)</span><span className="font-bold">₹ 5,000</span></div>
                </div>
                <div className="flex justify-between items-center pt-4 border-t border-slate-200"><span className="text-lg font-bold text-slate-600">Total Engagement Value</span><span className="text-2xl font-bold text-indigo-600">₹ 55,000</span></div>
              </div>
            )}
          </div>
          <div className="flex justify-between pt-6 mt-4 border-t border-slate-200">
            {step > 1 ? <button onClick={() => setStep(s => s - 1)} className="px-6 py-2 text-slate-500 font-medium hover:bg-slate-200 rounded-xl">Back</button> : <button onClick={onClose} className="px-6 py-2 text-slate-500 font-medium hover:bg-slate-200 rounded-xl">Cancel</button>}
            {step < 3 ? <button onClick={() => setStep(s => s + 1)} className="px-6 py-2 bg-indigo-600 text-white font-bold rounded-xl shadow-lg hover:bg-indigo-700 transition-colors">Continue</button> : <button onClick={() => { onSave(); onClose(); }} className="px-6 py-2 bg-emerald-600 text-white font-bold rounded-xl shadow-lg hover:bg-emerald-700 transition-colors">Create Engagement</button>}
          </div>
        </div>
      </div>
    </div>
  );
};

// 2. PROJECT DEEP DIVE
const ProjectDetailView = ({ project, onBack }) => {
  const [activeTab, setActiveTab] = useState('Task Management');
  const [tasks, setTasks] = useState(INITIAL_WBS);

  const toggleExpand = (id) => {
    setTasks(tasks.map(t => t.id === id ? { ...t, expanded: !t.expanded } : t));
  };

  return (
    <div className="h-full flex flex-col animate-in slide-in-from-right duration-300">
      <div className="bg-white p-6 border-b border-slate-200 flex justify-between items-center sticky top-0 z-10">
        <div className="flex items-center gap-4">
          <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-full text-slate-500 transition-colors"><ChevronLeft size={24} /></button>
          <div>
            <h1 className="text-2xl font-bold text-slate-800">{project.title}</h1>
            <p className="text-slate-500 text-sm flex items-center mt-1"><Building2 size={14} className="mr-1" /> {project.client} <span className="mx-2 text-slate-300">|</span> <span className="text-indigo-600 font-medium">Value: ₹ {project.budget.toLocaleString()}</span></p>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 border border-slate-200 text-slate-600 font-medium rounded-xl hover:bg-slate-50 text-sm flex items-center"><FileText size={16} className="mr-2" /> Audit Report</button>
          <button className="px-4 py-2 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-700 text-sm flex items-center"><Plus size={16} className="mr-2" /> New Invoice</button>
        </div>
      </div>

      <div className="px-6 pt-4 bg-white border-b border-slate-200">
        <div className="flex gap-6 overflow-x-auto">
          {['Overview', 'Task Management', 'Engagement Fees', 'Payment Status', 'Client Documents'].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} className={`pb-3 text-sm font-bold border-b-2 transition-all whitespace-nowrap ${activeTab === tab ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>{tab}</button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6 bg-slate-50">
        {activeTab === 'Overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm lg:col-span-2">
              <h3 className="font-bold text-slate-800 mb-6">Financial Summary</h3>
              <div className="flex items-center justify-around">
                <div className="text-center"><p className="text-xs text-slate-400 font-bold uppercase mb-1">Total Fees</p><p className="text-2xl font-bold text-slate-800">₹ {project.budget.toLocaleString()}</p></div>
                <div className="h-10 w-px bg-slate-200"></div>
                <div className="text-center"><p className="text-xs text-slate-400 font-bold uppercase mb-1">Invoiced</p><p className="text-2xl font-bold text-emerald-600">₹ {project.billed.toLocaleString()}</p></div>
                <div className="h-10 w-px bg-slate-200"></div>
                <div className="text-center"><p className="text-xs text-slate-400 font-bold uppercase mb-1">Received</p><p className="text-2xl font-bold text-indigo-600">₹ {project.received.toLocaleString()}</p></div>
              </div>
              <div className="mt-8">
                <div className="flex justify-between text-xs font-bold text-slate-500 mb-2"><span>Audit Completion</span><span>{project.progress}%</span></div>
                <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500" style={{ width: `${project.progress}%` }}></div></div>
              </div>
            </div>
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
              <h3 className="font-bold text-slate-800 mb-4">Team Utilization</h3>
              <div className="space-y-4">
                {['Rahul (Senior)', 'Arjun (Article)', 'Priya (Article)'].map((staff, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-100">
                    <div className="flex items-center gap-3"><div className="w-8 h-8 rounded-full bg-slate-200 flex items-center justify-center font-bold text-xs text-slate-600">{staff.charAt(0)}</div><div><p className="text-sm font-semibold">{staff.split(' ')[0]}</p><p className="text-[10px] text-slate-400">{staff.split(' ')[1]}</p></div></div><span className="text-sm font-bold text-slate-700">12 hrs</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'Task Management' && (
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col h-full">
            <div className="p-4 border-b border-slate-100 flex justify-between items-center bg-white sticky top-0 z-10">
              <div className="flex gap-3">
                <div className="flex items-center gap-2 border border-slate-200 rounded-lg px-3 py-1.5 bg-slate-50">
                  <span className="text-xs font-bold text-slate-600">All Status</span><ChevronDown size={14} className="text-slate-400" />
                </div>
                <button className="px-3 py-1.5 border border-slate-200 rounded-lg text-xs font-medium text-slate-600 flex items-center">Import Checklist</button>
              </div>
              <button className="bg-indigo-600 text-white px-3 py-1.5 rounded-lg text-xs font-bold flex items-center shadow-md"><Plus size={14} className="mr-1" /> Add Task</button>
            </div>

            <div className="flex-1 overflow-auto">
              <table className="w-full text-left border-collapse min-w-[1000px]">
                <thead className="bg-slate-50 text-[11px] font-bold text-slate-500 uppercase sticky top-0 z-10 text-center">
                  <tr>
                    <th className="px-4 py-3 border-b border-r w-12">S.No</th>
                    <th className="px-6 py-3 border-b border-r text-left w-64">Audit Procedure</th>
                    <th className="px-4 py-3 border-b border-r">Duration</th>
                    <th className="px-4 py-3 border-b border-r">Start Date</th>
                    <th className="px-4 py-3 border-b border-r">End Date</th>
                    <th className="px-4 py-3 border-b border-r">Progress</th>
                    <th className="px-4 py-3 border-b border-r">Dep.</th>
                    <th className="px-4 py-3 border-b">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {tasks.map(task => (
                    <React.Fragment key={task.id}>
                      <tr className="bg-slate-50/50 hover:bg-slate-100 font-bold text-slate-700">
                        <td className="px-4 py-3 border-r text-center">{task.sNo}</td>
                        <td className="px-6 py-3 border-r flex items-center cursor-pointer" onClick={() => toggleExpand(task.id)}>
                          {task.children.length > 0 ? (task.expanded ? <ChevronDownIcon size={14} className="mr-2" /> : <ChevronRightIcon size={14} className="mr-2" />) : <span className="w-5 mr-1"></span>}
                          {task.name}
                        </td>
                        <td className="px-4 py-3 border-r text-center text-slate-500">{task.duration}</td>
                        <td className="px-4 py-3 border-r text-center">{task.start}</td>
                        <td className="px-4 py-3 border-r text-center">{task.end}</td>
                        <td className="px-4 py-3 border-r text-center">{task.progress}</td>
                        <td className="px-4 py-3 border-r text-center text-slate-400"></td>
                        <td className="px-4 py-3 text-center"><MoreVertical size={14} className="mx-auto text-slate-400" /></td>
                      </tr>
                      {task.expanded && task.children.map(child => (
                        <tr key={child.id} className="hover:bg-indigo-50/30 transition-colors">
                          <td className="px-4 py-3 border-r text-center"></td>
                          <td className="px-6 py-3 border-r pl-10 flex items-center text-slate-600 font-medium">
                            <ArrowDownRight size={12} className="mr-2 text-slate-300" /> {child.name}
                            <span className="ml-2 text-[10px] text-slate-400 border px-1 rounded bg-white">By: {child.assignee}</span>
                          </td>
                          <td className="px-4 py-3 border-r text-center text-slate-500">{child.duration}</td>
                          <td className="px-4 py-3 border-r text-center">{child.start}</td>
                          <td className="px-4 py-3 border-r text-center">{child.end}</td>
                          <td className="px-4 py-3 border-r text-center text-indigo-600 font-bold">{child.progress}</td>
                          <td className="px-4 py-3 border-r text-center text-indigo-500 font-mono">{child.dep}</td>
                          <td className="px-4 py-3 text-center"><MoreVertical size={14} className="mx-auto text-slate-400" /></td>
                        </tr>
                      ))}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'Engagement Fees' && (
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 bg-slate-50 border-b border-slate-100 flex justify-between items-center"><h3 className="font-bold text-slate-700">Fees Schedule</h3><span className="bg-emerald-100 text-emerald-800 px-3 py-1 rounded-lg text-sm font-bold">Total Value: ₹ 1,50,000</span></div>
            <table className="w-full text-left">
              <thead className="text-xs uppercase text-slate-400 font-bold border-b border-slate-100"><tr><th className="px-6 py-4">Fee Description</th><th className="px-6 py-4">Qty</th><th className="px-6 py-4">Rate</th><th className="px-6 py-4 text-right">Amount</th></tr></thead>
              <tbody className="divide-y divide-slate-50">
                {INITIAL_FEES.map(item => (
                  <tr key={item.id}><td className="px-6 py-4 font-medium text-slate-700">{item.item}</td><td className="px-6 py-4 text-slate-500">{item.qty}</td><td className="px-6 py-4 text-slate-500">₹ {item.rate.toLocaleString()}</td><td className="px-6 py-4 text-right font-bold text-slate-800">₹ {item.amount.toLocaleString()}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'Payment Status' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col items-center justify-center">
                <p className="text-xs text-slate-400 font-bold uppercase mb-2">Total Invoiced</p>
                <p className="text-3xl font-bold text-indigo-900">₹ {project.billed.toLocaleString()}</p>
              </div>
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col items-center justify-center">
                <p className="text-xs text-slate-400 font-bold uppercase mb-2">Total Received</p>
                <p className="text-3xl font-bold text-emerald-600">₹ {project.received.toLocaleString()}</p>
              </div>
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col items-center justify-center">
                <p className="text-xs text-slate-400 font-bold uppercase mb-2">Balance Recoverable</p>
                <p className="text-3xl font-bold text-rose-600">₹ {(project.billed - project.received).toLocaleString()}</p>
              </div>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="p-4 bg-slate-50 border-b border-slate-100"><h3 className="font-bold text-slate-700">Receipt History</h3></div>
              <table className="w-full text-left">
                <thead className="text-xs uppercase text-slate-400 font-bold border-b border-slate-100"><tr><th className="px-6 py-4">Date</th><th className="px-6 py-4">Description</th><th className="px-6 py-4">Mode</th><th className="px-6 py-4">Amount</th><th className="px-6 py-4">Status</th></tr></thead>
                <tbody className="divide-y divide-slate-50">
                  {INITIAL_PAYMENTS.map(pay => (
                    <tr key={pay.id}>
                      <td className="px-6 py-4 text-slate-500">{pay.date}</td>
                      <td className="px-6 py-4 font-medium text-slate-700">{pay.type}</td>
                      <td className="px-6 py-4 text-slate-500">{pay.mode}</td>
                      <td className="px-6 py-4 font-bold text-slate-800">₹ {pay.amount.toLocaleString()}</td>
                      <td className="px-6 py-4"><StatusBadge status={pay.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'Client Documents' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
              <h3 className="font-bold text-slate-800 mb-4">Pending from Client (PBC List)</h3>
              <ul className="space-y-3">
                {['Bank Statements (FY24)', 'Salary Register (March)', 'GST Returns (Annual)'].map((doc, i) => (
                  <li key={i} className="flex items-center justify-between p-3 bg-amber-50 text-amber-800 rounded-lg border border-amber-100 text-sm">
                    <span>{doc}</span>
                    <span className="text-xs font-bold uppercase bg-amber-200/50 px-2 py-1 rounded">Requested</span>
                  </li>
                ))}
              </ul>
              <button className="mt-4 w-full py-2 border-2 border-dashed border-indigo-200 text-indigo-600 rounded-xl text-sm font-bold hover:bg-indigo-50">+ Request New Document</button>
            </div>
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
              <h3 className="font-bold text-slate-800 mb-4">Uploaded Evidence</h3>
              <div className="grid grid-cols-3 gap-3">
                {[1, 2, 3].map(i => (
                  <div key={i} className="aspect-square bg-slate-50 rounded-xl flex flex-col items-center justify-center text-slate-500 hover:bg-indigo-50 hover:text-indigo-600 cursor-pointer border border-slate-200 hover:border-indigo-200 transition-all p-4 text-center">
                    <FileText size={32} className="mb-3" />
                    <span className="text-xs font-medium">Trial Balance.xlsx</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// --- MAIN APP ---
function App() {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [currentView, setCurrentView] = useState('list');
  const [selectedProject, setSelectedProject] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [orders, setOrders] = useState([]); // State for real orders

  // --- EFFECTS ---
  React.useEffect(() => {
    const fetchOrders = async () => {
      try {
        const res = await fetch('/api/orders');
        if (res.ok) {
          const data = await res.json();
          setOrders(data);
        } else {
          console.error("Failed to fetch orders");
        }
      } catch (error) {
        console.error("Error fetching orders:", error);
      }
    };

    if (activeTab === 'ServiceRequests') {
      fetchOrders();
    }
  }, [activeTab]);

  // --- ACTIONS ---
  const handleLogout = () => {
    // Clear any auth tokens
    localStorage.removeItem('userInfo');
    // Redirect to login or home
    window.location.href = '/login';
  };

  // DASHBOARD VIEW
  const DashboardView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-8"><h1 className="text-2xl font-bold text-slate-800">Overview</h1><p className="text-slate-500">Practice Performance & Alerts</p></div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Total Revenue', val: '₹ 15.2L', icon: DollarSign, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Active Projects', val: '24', icon: Layers, color: 'text-indigo-600', bg: 'bg-indigo-50' },
          { label: 'Pending Tasks', val: '142', icon: CheckSquare, color: 'text-amber-600', bg: 'bg-amber-50' },
          { label: 'Unbilled Amount', val: '₹ 4.5L', icon: AlertCircle, color: 'text-rose-600', bg: 'bg-rose-50' }
        ].map((stat, i) => (
          <div key={i} className="bg-white p-6 rounded-2xl border border-slate-100 shadow-sm flex items-start justify-between">
            <div><p className="text-slate-500 text-sm font-medium mb-1">{stat.label}</p><h3 className="text-2xl font-bold text-slate-800">{stat.val}</h3></div>
            <div className={`p-3 rounded-xl ${stat.bg} ${stat.color}`}><stat.icon size={20} /></div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm h-80 flex flex-col items-center justify-center text-slate-400">
          <PieChart size={32} className="mb-2" /><p>Revenue Distribution Chart</p>
        </div>
        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm h-80 flex flex-col items-center justify-center text-slate-400">
          <BarChart size={32} className="mb-2" /><p>Task Completion Trends</p>
        </div>
      </div>
    </div>
  );

  // PROJECT LIST VIEW
  const ProjectListView = () => (
    <div className="animate-in fade-in zoom-in duration-300 h-full flex flex-col">
      <div className="flex justify-between items-center mb-6">
        <div><h2 className="text-2xl font-bold text-slate-800">Engagements</h2><p className="text-slate-500">Manage Audit & Consulting Projects</p></div>
        <button onClick={() => setCurrentView('wizard')} className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-sm font-medium flex items-center shadow-lg"><Plus size={18} className="mr-2" /> New Engagement</button>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {INITIAL_PROJECTS.map(proj => (
          <div key={proj.id} onClick={() => { setSelectedProject(proj); setCurrentView('detail'); }} className="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md cursor-pointer group">
            <div className="flex justify-between items-start mb-3">
              <div className="p-2 bg-indigo-50 text-indigo-600 rounded-lg">
                {proj.type === 'Audit' ? <Scale size={20} /> : proj.type === 'Registration' ? <Globe size={20} /> : <Briefcase size={20} />}
              </div>
              <StatusBadge status={proj.status} />
            </div>
            <h3 className="font-bold text-lg text-slate-800 mb-1 group-hover:text-indigo-600">{proj.title}</h3>
            <p className="text-sm text-slate-500 mb-4">{proj.client}</p>
            <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden"><div className="h-full bg-indigo-500" style={{ width: `${proj.progress}%` }}></div></div>
          </div>
        ))}
      </div>
    </div>
  );

  // GENERIC LIST VIEW COMPONENT (Reusable for ToDo, Quotation, Finance, etc.)
  const GenericListView = ({ title, sub, data, columns }) => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="flex justify-between items-center mb-6">
        <div><h2 className="text-2xl font-bold text-slate-800">{title}</h2><p className="text-slate-500">{sub}</p></div>
        <button className="bg-indigo-600 text-white px-4 py-2 rounded-xl text-sm font-medium flex items-center shadow-lg"><Plus size={18} className="mr-2" /> Create New</button>
      </div>
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
            <tr>{columns.map((col, i) => <th key={i} className="px-6 py-4">{col}</th>)}<th className="px-6 py-4">Action</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {data.map((item, i) => (
              <tr key={i} className="hover:bg-slate-50">
                {Object.values(item).slice(1).map((val, j) => ( // Skip ID
                  <td key={j} className="px-6 py-4 text-sm text-slate-700 font-medium">
                    {['High', 'Medium', 'Low', 'Sent', 'Draft', 'Paid', 'Overdue', 'Processed', 'Pending', 'New', 'Assigned', 'In Progress'].includes(val) ? <StatusBadge status={val} /> : val}
                  </td>
                ))}
                <td className="px-6 py-4"><MoreVertical size={16} className="text-slate-400 cursor-pointer hover:text-indigo-600" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  // SERVICES CATALOG VIEW
  const ServicesView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-6"><h2 className="text-2xl font-bold text-slate-800">Service Catalog</h2><p className="text-slate-500">Master List of Offerings</p></div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {Object.entries(SERVICE_CATALOG).map(([cat, services]) => (
          <div key={cat} className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <div className="flex items-center gap-3 mb-4 text-indigo-600">
              {cat.includes('Industrial') ? <Factory /> : cat.includes('ISO') ? <Stamp /> : cat.includes('Tax') ? <Receipt /> : cat.includes('Registration') ? <Globe /> : <Briefcase />}
              <h3 className="font-bold text-lg text-slate-800">{cat}</h3>
            </div>
            <ul className="space-y-2">
              {services.map(s => <li key={s} className="text-sm text-slate-600 flex items-center"><div className="w-1.5 h-1.5 rounded-full bg-slate-300 mr-2"></div>{s}</li>)}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );

  // REPORTS VIEW (Mock)
  const ReportsView = () => (
    <div className="animate-in fade-in zoom-in duration-300">
      <div className="mb-6"><h2 className="text-2xl font-bold text-slate-800">Reports Center</h2><p className="text-slate-500">Generated Compliance & MIS Reports</p></div>
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase">
            <tr><th className="px-6 py-4">Report Name</th><th className="px-6 py-4">Category</th><th className="px-6 py-4">Generated Date</th><th className="px-6 py-4">Action</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {INITIAL_REPORTS.map((report) => (
              <tr key={report.id} className="hover:bg-slate-50">
                <td className="px-6 py-4 text-sm font-medium text-slate-700 flex items-center"><FileSpreadsheet size={16} className="mr-2 text-emerald-600" />{report.name}</td>
                <td className="px-6 py-4 text-sm text-slate-600">{report.type}</td>
                <td className="px-6 py-4 text-sm text-slate-500">{report.generated}</td>
                <td className="px-6 py-4"><button className="text-indigo-600 hover:text-indigo-800 text-xs font-bold flex items-center"><Download size={14} className="mr-1" /> Download</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      <aside className={`${sidebarCollapsed ? 'w-20' : 'w-72'} bg-white h-full border-r border-slate-200 flex flex-col py-6 z-20 shadow-xl transition-all duration-300`} onMouseEnter={() => setSidebarCollapsed(false)} onMouseLeave={() => setSidebarCollapsed(true)}>
        <div className="flex items-center justify-center mb-8 px-4 h-12 overflow-hidden whitespace-nowrap">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-lg shrink-0">VR</div>
          <span className={`ml-3 font-bold text-xl tracking-tight text-slate-800 transition-opacity duration-300 ${sidebarCollapsed ? 'opacity-0 w-0' : 'opacity-100'}`}>VR <span className="text-indigo-600">Here</span></span>
        </div>
        <div className="space-y-1 flex-1 w-full px-3 overflow-y-auto">
          <SidebarItem icon={LayoutDashboard} label="Dashboard" active={activeTab === 'Dashboard'} onClick={() => setActiveTab('Dashboard')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Layers} label="Projects" active={activeTab === 'Projects'} onClick={() => { setActiveTab('Projects'); setCurrentView('list'); }} collapsed={sidebarCollapsed} />
          <SidebarItem icon={MessageCircle} label="Service Requests" active={activeTab === 'ServiceRequests'} onClick={() => setActiveTab('ServiceRequests')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={CheckSquare} label="To Do" active={activeTab === 'ToDo'} onClick={() => setActiveTab('ToDo')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={FileText} label="Quotation" active={activeTab === 'Quotation'} onClick={() => setActiveTab('Quotation')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={DollarSign} label="Finance" active={activeTab === 'Finance'} onClick={() => setActiveTab('Finance')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={BarChart} label="Reports" active={activeTab === 'Reports'} onClick={() => setActiveTab('Reports')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Users} label="Payroll" active={activeTab === 'Payroll'} onClick={() => setActiveTab('Payroll')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={ServiceIcon} label="Services" active={activeTab === 'Services'} onClick={() => setActiveTab('Services')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={BookOpen} label="Library" active={activeTab === 'Library'} onClick={() => setActiveTab('Library')} collapsed={sidebarCollapsed} />
          <SidebarItem icon={Settings} label="Settings" active={activeTab === 'Settings'} onClick={() => setActiveTab('Settings')} collapsed={sidebarCollapsed} />

          <div className="mt-auto pt-4 border-t border-slate-100 mx-3">
            <SidebarItem icon={LogOut} label="Logout" active={false} onClick={handleLogout} collapsed={sidebarCollapsed} />
          </div>
        </div>
      </aside>
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <div className="flex-1 overflow-y-auto p-8">
          {activeTab === 'Dashboard' && <DashboardView />}
          {activeTab === 'Projects' && currentView === 'list' && <ProjectListView />}
          {activeTab === 'Projects' && currentView === 'detail' && <ProjectDetailView project={selectedProject} onBack={() => setCurrentView('list')} />}
          {activeTab === 'Projects' && currentView === 'list' && <ProjectListView />}
          {activeTab === 'Projects' && currentView === 'detail' && <ProjectDetailView project={selectedProject} onBack={() => setCurrentView('list')} />}
          {activeTab === 'ServiceRequests' && <GenericListView
            title="Service Requests"
            sub="Incoming Inquiries from Website"
            data={orders.map(o => ({
              id: o._id,
              client: o.clientName,
              service: o.serviceName,
              date: new Date(o.date).toLocaleDateString(),
              status: o.status,
              assignedTo: '-'
            }))}
            columns={['Client', 'Service', 'Date', 'Status', 'Assigned To']}
          />}
          {activeTab === 'ToDo' && <GenericListView title="Task List" sub="Ad-hoc Compliance Tasks" data={INITIAL_TODO} columns={['Task', 'Due Date', 'Priority', 'Assignee']} />}
          {activeTab === 'Quotation' && <GenericListView title="Quotations" sub="Proposals Sent to Clients" data={INITIAL_QUOTES} columns={['Client', 'Subject', 'Amount', 'Status']} />}
          {activeTab === 'Finance' && <GenericListView title="Invoices" sub="Billing & Receivables" data={INITIAL_INVOICES} columns={['Client', 'Date', 'Amount', 'Status']} />}
          {activeTab === 'Payroll' && <GenericListView title="Staff Payroll" sub="Salary Processing" data={INITIAL_PAYROLL} columns={['Name', 'Role', 'Days Present', 'Net Salary', 'Status']} />}
          {activeTab === 'Services' && <ServicesView />}
          {activeTab === 'Library' && <GenericListView title="Client Directory" sub="Master Data of Parties" data={INITIAL_PARTIES} columns={['Name', 'Type', 'Contact']} />}
          {activeTab === 'Reports' && <ReportsView />}
          {activeTab === 'Settings' && <div className="flex h-full items-center justify-center text-slate-400 flex-col"><Settings size={48} className="mb-4 opacity-20" /><p>System Settings Placeholder</p></div>}
          {currentView === 'wizard' && <ProjectWizard onClose={() => setCurrentView('list')} onSave={() => { /* Save Logic */ }} />}
        </div>
      </main>
    </div>
  );
}

export default App;