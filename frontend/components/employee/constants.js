import {
  LayoutDashboard,
  Briefcase,
  FolderKanban,
  CheckSquare,
  Clock3,
  FileText,
  ClipboardList,
  MessageSquare,
  IndianRupee,
  Bell,
  ShieldCheck,
  DollarSign,
  Users,
  Layers
} from 'lucide-react';

export const ORDER_STATUSES = [
  'Pending Documents',
  'Documents Verified',
  'Processing at Portal',
  'Waiting for Clarification',
  'Completed'
];

export const EMPLOYEE_TABS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'queue', label: 'Work Queue', icon: Briefcase },
  { id: 'processing', label: 'Order Processing', icon: FolderKanban },
  { id: 'tasks', label: 'Task Management', icon: CheckSquare },
  { id: 'time', label: 'Time Tracking', icon: Clock3 },
  { id: 'documents', label: 'Documents', icon: FileText },
  { id: 'requirements', label: 'Requirements', icon: ClipboardList },
  { id: 'support', label: 'Support', icon: MessageSquare },
  { id: 'commercials', label: 'Commercials', icon: IndianRupee },
  { id: 'finance', label: 'Finance', icon: DollarSign },
  { id: 'hrms', label: 'HRMS Portal', icon: Users },
  { id: 'services', label: 'Services Master', icon: Layers },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: ShieldCheck }
];


