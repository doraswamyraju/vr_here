import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

import EmployeeSidebar from './components/employee/EmployeeSidebar';
import EmployeeTopbar from './components/employee/EmployeeTopbar';
import DashboardOverviewModule from './components/employee/DashboardOverviewModule';
import WorkQueueModule from './components/employee/WorkQueueModule';
import OrderProcessingModule from './components/employee/OrderProcessingModule';
import TaskManagementModule from './components/employee/TaskManagementModule';
import TimeTrackingModule from './components/employee/TimeTrackingModule';
import DocumentsModule from './components/employee/DocumentsModule';
import RequirementsModule from './components/employee/RequirementsModule';
import SupportModule from './components/employee/SupportModule';
import CommercialsModule from './components/employee/CommercialsModule';
import NotificationsModule from './components/employee/NotificationsModule';
import SecurityModule from './components/employee/SecurityModule';
import { dummyNotifications, dummyTickets } from './components/employee/mockData';

const SHIFT_STORAGE_KEY = 'employee_shift_state_v2';
const ACTIVE_TASK_STORAGE_KEY = 'employee_active_task_v2';

const formatDuration = (totalSeconds) => {
  const safe = Math.max(0, Number(totalSeconds || 0));
  const h = Math.floor(safe / 3600);
  const m = Math.floor((safe % 3600) / 60);
  const s = safe % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};

const EmployeeApp = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [userInfo, setUserInfo] = useState(null);
  const [orders, setOrders] = useState([]);
  const [selectedOrderId, setSelectedOrderId] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [tickets, setTickets] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [isClockedIn, setIsClockedIn] = useState(false);
  const [shiftStartedAt, setShiftStartedAt] = useState(null);
  const [shiftElapsedSeconds, setShiftElapsedSeconds] = useState(0);
  const [activeTaskSession, setActiveTaskSession] = useState(null);
  const [activeTaskElapsedSeconds, setActiveTaskElapsedSeconds] = useState(0);

  const navigate = useNavigate();
  const shiftIntervalRef = useRef(null);
  const activeTaskIntervalRef = useRef(null);

  const authConfig = useMemo(() => (
    userInfo?.token
      ? { headers: { Authorization: `Bearer ${userInfo.token}` } }
      : null
  ), [userInfo]);

  const selectedOrder = useMemo(
    () => orders.find((order) => order._id === selectedOrderId) || null,
    [orders, selectedOrderId]
  );

  const activeTaskDetails = useMemo(() => {
    if (!activeTaskSession?.orderId || !activeTaskSession?.taskId) return null;
    const order = orders.find((item) => item._id === activeTaskSession.orderId);
    const task = order?.tasks?.find((item) => item._id === activeTaskSession.taskId);
    return {
      orderId: activeTaskSession.orderId,
      taskId: activeTaskSession.taskId,
      serviceName: order?.serviceName || activeTaskSession.serviceName || 'Unknown Service',
      taskTitle: task?.title || activeTaskSession.taskTitle || 'Unknown Task'
    };
  }, [activeTaskSession, orders]);

  const fetchOrders = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/orders', authConfig);
      setOrders(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch employee orders:', error);
    }
  }, [authConfig]);

  const fetchExtras = useCallback(async () => {
    if (!authConfig) return;

    try {
      const { data } = await axios.get('/api/notifications', authConfig);
      setNotifications(Array.isArray(data) ? data : dummyNotifications);
    } catch (error) {
      setNotifications(dummyNotifications);
    }

    try {
      const { data } = await axios.get('/api/tickets', authConfig);
      setTickets(Array.isArray(data) ? data : dummyTickets);
    } catch (error) {
      setTickets(dummyTickets);
    }
  }, [authConfig]);

  useEffect(() => {
    const stored = localStorage.getItem('userInfo');
    if (!stored) {
      navigate('/login');
      return;
    }

    const parsed = JSON.parse(stored);
    if (parsed.role !== 'employee' && parsed.role !== 'admin') {
      alert('Access denied. Employee dashboard only.');
      navigate('/');
      return;
    }

    setUserInfo(parsed);
  }, [navigate]);

  useEffect(() => {
    if (!userInfo) return;
    fetchOrders();
    fetchExtras();
  }, [userInfo, fetchOrders, fetchExtras]);

  useEffect(() => {
    const rawShift = localStorage.getItem(SHIFT_STORAGE_KEY);
    if (rawShift) {
      try {
        const parsed = JSON.parse(rawShift);
        if (parsed?.isClockedIn && parsed?.shiftStartedAt) {
          setIsClockedIn(true);
          setShiftStartedAt(parsed.shiftStartedAt);
          const elapsed = Math.floor((Date.now() - new Date(parsed.shiftStartedAt).getTime()) / 1000);
          setShiftElapsedSeconds(Math.max(0, elapsed));
        }
      } catch (error) {
        localStorage.removeItem(SHIFT_STORAGE_KEY);
      }
    }

    const rawTask = localStorage.getItem(ACTIVE_TASK_STORAGE_KEY);
    if (rawTask) {
      try {
        const parsed = JSON.parse(rawTask);
        if (parsed?.orderId && parsed?.taskId && parsed?.startedAt) {
          setActiveTaskSession(parsed);
          const elapsed = Math.floor((Date.now() - new Date(parsed.startedAt).getTime()) / 1000);
          setActiveTaskElapsedSeconds(Math.max(0, elapsed));
        }
      } catch (error) {
        localStorage.removeItem(ACTIVE_TASK_STORAGE_KEY);
      }
    }
  }, []);

  useEffect(() => {
    if (isClockedIn && shiftStartedAt) {
      shiftIntervalRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - new Date(shiftStartedAt).getTime()) / 1000);
        setShiftElapsedSeconds(Math.max(0, elapsed));
      }, 1000);
    }
    return () => {
      if (shiftIntervalRef.current) {
        clearInterval(shiftIntervalRef.current);
        shiftIntervalRef.current = null;
      }
    };
  }, [isClockedIn, shiftStartedAt]);

  useEffect(() => {
    if (activeTaskSession?.startedAt) {
      activeTaskIntervalRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - new Date(activeTaskSession.startedAt).getTime()) / 1000);
        setActiveTaskElapsedSeconds(Math.max(0, elapsed));
      }, 1000);
    }
    return () => {
      if (activeTaskIntervalRef.current) {
        clearInterval(activeTaskIntervalRef.current);
        activeTaskIntervalRef.current = null;
      }
    };
  }, [activeTaskSession]);

  const refreshAll = () => {
    fetchOrders();
    fetchExtras();
  };

  const clockIn = () => {
    const startedAt = new Date().toISOString();
    setIsClockedIn(true);
    setShiftStartedAt(startedAt);
    setShiftElapsedSeconds(0);
    localStorage.setItem(SHIFT_STORAGE_KEY, JSON.stringify({ isClockedIn: true, shiftStartedAt: startedAt }));
  };

  const clockOut = () => {
    setIsClockedIn(false);
    setShiftStartedAt(null);
    setShiftElapsedSeconds(0);
    localStorage.removeItem(SHIFT_STORAGE_KEY);
  };

  const openOrderInProcessing = (order) => {
    setSelectedOrderId(order._id);
    setActiveTab('processing');
  };

  const handleStatusChange = async (orderId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/status`, { status }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update order status.');
    }
  };

  const handleTaskStatusChange = async (orderId, taskId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}`, { status }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update task status.');
    }
  };

  const handleUpdateSubtask = async (orderId, taskId, subtaskId, payload) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}/subtasks/${subtaskId}`, payload, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update subtask.');
    }
  };

  const handleLogTime = async (orderId, taskId, minutes, notes) => {
    if (!authConfig) return;
    try {
      await axios.post(`/api/orders/${orderId}/tasks/${taskId}/time-log`, { minutes, notes }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to log task time.');
    }
  };

  const startTaskSession = async ({ orderId, taskId, serviceName, taskTitle }) => {
    if (activeTaskSession && (activeTaskSession.orderId !== orderId || activeTaskSession.taskId !== taskId)) {
      alert('Pause or complete the current task before starting another one.');
      return;
    }

    if (activeTaskSession) return;

    const startedAt = new Date().toISOString();
    const nextSession = { orderId, taskId, startedAt, serviceName, taskTitle };
    setActiveTaskSession(nextSession);
    setActiveTaskElapsedSeconds(0);
    localStorage.setItem(ACTIVE_TASK_STORAGE_KEY, JSON.stringify(nextSession));
    await handleTaskStatusChange(orderId, taskId, 'In Progress');
  };

  const pauseTaskSession = async () => {
    if (!activeTaskSession?.orderId || !activeTaskSession?.taskId || !activeTaskSession?.startedAt) return;
    const elapsedSeconds = Math.floor((Date.now() - new Date(activeTaskSession.startedAt).getTime()) / 1000);
    const minutes = Math.max(1, Math.round(elapsedSeconds / 60));
    await handleLogTime(
      activeTaskSession.orderId,
      activeTaskSession.taskId,
      minutes,
      `Timer log (${formatDuration(elapsedSeconds)})`
    );

    setActiveTaskSession(null);
    setActiveTaskElapsedSeconds(0);
    localStorage.removeItem(ACTIVE_TASK_STORAGE_KEY);
  };

  const completeTaskSession = async () => {
    if (!activeTaskSession?.orderId || !activeTaskSession?.taskId) return;
    await pauseTaskSession();
    await handleTaskStatusChange(activeTaskSession.orderId, activeTaskSession.taskId, 'Completed');
  };

  const handleUploadCertificate = async (file) => {
    if (!authConfig || !selectedOrder) return;

    const formData = new FormData();
    formData.append('document', file);

    setIsUploading(true);
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          Authorization: `Bearer ${userInfo.token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      alert('Final certificate uploaded successfully.');
      await fetchOrders();
    } catch (error) {
      alert('Unable to upload final certificate.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userInfo');
    navigate('/login');
  };

  const renderActiveModule = () => {
    switch (activeTab) {
      case 'dashboard':
        return <DashboardOverviewModule userInfo={userInfo} orders={orders} onOpenOrder={openOrderInProcessing} />;
      case 'queue':
        return <WorkQueueModule orders={orders} onOpenOrder={openOrderInProcessing} />;
      case 'processing':
        return (
          <OrderProcessingModule
            orders={orders}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onStatusChange={handleStatusChange}
            onUploadCertificate={handleUploadCertificate}
            isUploading={isUploading}
          />
        );
      case 'tasks':
        return (
          <TaskManagementModule
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onTaskStatusChange={handleTaskStatusChange}
            onUpdateSubtask={handleUpdateSubtask}
            activeTaskSession={activeTaskSession}
            activeTaskElapsedSeconds={activeTaskElapsedSeconds}
            onStartTask={startTaskSession}
            onPauseTask={pauseTaskSession}
            onCompleteTask={completeTaskSession}
          />
        );
      case 'time':
        return (
          <TimeTrackingModule
            orders={orders}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onLogTime={handleLogTime}
            userInfo={userInfo}
            activeTaskSession={activeTaskSession}
            activeTaskElapsedSeconds={activeTaskElapsedSeconds}
          />
        );
      case 'documents':
        return <DocumentsModule selectedOrder={selectedOrder} />;
      case 'requirements':
        return <RequirementsModule selectedOrder={selectedOrder} />;
      case 'support':
        return <SupportModule tickets={tickets} />;
      case 'commercials':
        return <CommercialsModule selectedOrder={selectedOrder} />;
      case 'notifications':
        return <NotificationsModule notifications={notifications} />;
      case 'security':
        return <SecurityModule />;
      default:
        return <DashboardOverviewModule userInfo={userInfo} orders={orders} onOpenOrder={openOrderInProcessing} />;
    }
  };

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      <EmployeeSidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        onLogout={handleLogout}
      />

      <main className="flex-1 flex flex-col h-full overflow-hidden">
        <EmployeeTopbar
          activeTab={activeTab}
          userInfo={userInfo}
          onRefresh={refreshAll}
          isClockedIn={isClockedIn}
          shiftElapsedLabel={formatDuration(shiftElapsedSeconds)}
          onClockIn={clockIn}
          onClockOut={clockOut}
          activeTaskDetails={activeTaskDetails}
          activeTaskElapsedLabel={formatDuration(activeTaskElapsedSeconds)}
          onPauseTask={pauseTaskSession}
          onCompleteTask={completeTaskSession}
        />
        <div className="flex-1 overflow-y-auto p-6 md:p-8">{renderActiveModule()}</div>
      </main>
    </div>
  );
};

export default EmployeeApp;
