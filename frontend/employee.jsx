import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

import EmployeeSidebar from './components/employee/EmployeeSidebar';
import EmployeeTopbar from './components/employee/EmployeeTopbar';
import DashboardOverviewModule from './components/employee/DashboardOverviewModule';
import WorkQueueModule from './components/employee/WorkQueueModule';
import OrderProcessingModule from './components/employee/OrderProcessingModule';
import { TaskManagementModule } from './modules/orders/v1.1';
import TimeTrackingModule from './components/employee/TimeTrackingModule';
import DocumentsModule from './components/employee/DocumentsModule';
import RequirementsModule from './components/employee/RequirementsModule';
import SupportModule from './components/employee/SupportModule';
import CommercialsModule from './components/employee/CommercialsModule';
import NotificationsModule from './components/employee/NotificationsModule';
import SecurityModule from './components/employee/SecurityModule';
import FinanceModule from './components/admin/finance/FinanceModule';
import { dummyTickets } from './components/employee/mockData';
import { useNotifications, NotificationsFeed, InAppBanner } from './modules/notifications/v1.1';
import HRMSModule from './modules/hrms/v1.1/index.jsx';

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
  const [todos, setTodos] = useState([]);
  const [selectedOrderId, setSelectedOrderId] = useState(null);
  
  const {
    notifications,
    activeBannerNotification,
    setActiveBannerNotification,
    unreadCount,
    markRead,
    markAllRead
  } = useNotifications(userInfo?.token);

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

  const fetchTodos = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/todos', authConfig);
      setTodos(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch employee tasks:', error);
    }
  }, [authConfig]);

  const fetchAttendanceStatus = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/attendance/my-status', authConfig);
      const openSession = data?.openSession || null;
      if (openSession?.clockInAt) {
        setIsClockedIn(true);
        setShiftStartedAt(openSession.clockInAt);
        const elapsed = Math.floor((Date.now() - new Date(openSession.clockInAt).getTime()) / 1000);
        setShiftElapsedSeconds(Math.max(0, elapsed));
      } else {
        setIsClockedIn(false);
        setShiftStartedAt(null);
        setShiftElapsedSeconds(0);
      }
    } catch (error) {
      console.error('Failed to fetch attendance status:', error);
    }
  }, [authConfig]);

  const fetchExtras = useCallback(async () => {
    if (!authConfig) return;

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
    fetchTodos();
    fetchExtras();
    fetchAttendanceStatus();
  }, [userInfo, fetchOrders, fetchTodos, fetchExtras, fetchAttendanceStatus]);

  useEffect(() => {
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
    fetchTodos();
    fetchExtras();
    fetchAttendanceStatus();
  };

  const clockIn = async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.post('/api/attendance/clock-in', { source: 'employee-dashboard' }, authConfig);
      const startedAt = data?.session?.clockInAt || new Date().toISOString();
      setIsClockedIn(true);
      setShiftStartedAt(startedAt);
      setShiftElapsedSeconds(0);
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to clock in.');
    }
  };

  const clockOut = async () => {
    if (!authConfig) return;
    try {
      await axios.post('/api/attendance/clock-out', {}, authConfig);
      setIsClockedIn(false);
      setShiftStartedAt(null);
      setShiftElapsedSeconds(0);
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to clock out.');
    }
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
      await fetchTodos();
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

  const handleUpdateRequirementStatus = async (orderId, requirementId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/requirements/${requirementId}/status`, { status }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update requirement status.');
    }
  };

  const handleRaiseRequirement = async (orderId, payload) => {
    if (!authConfig) return;
    try {
      await axios.post(`/api/orders/${orderId}/requirements`, payload, authConfig);
      await fetchOrders();
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to raise requirement.');
    }
  };

  const startTaskSession = async ({ orderId, taskId, serviceName, taskTitle }) => {
    if (!isClockedIn) {
      alert('Please clock in before starting a task timer.');
      return;
    }

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

  const handleTodoStatusChange = async (todoId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/todos/${todoId}`, { status }, authConfig);
      await fetchTodos();
    } catch (error) {
      alert('Unable to update todo status.');
    }
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
        return <DashboardOverviewModule userInfo={userInfo} orders={orders} todos={todos} onOpenOrder={openOrderInProcessing} isClockedIn={isClockedIn} onTodoStatusChange={handleTodoStatusChange} />;
      case 'queue':
        return <WorkQueueModule orders={orders} todos={todos} onOpenOrder={openOrderInProcessing} onTodoStatusChange={handleTodoStatusChange} isClockedIn={isClockedIn} />;
      case 'processing':
        return (
          <OrderProcessingModule
            orders={orders}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onStatusChange={handleStatusChange}
            onUploadCertificate={handleUploadCertificate}
            isUploading={isUploading}
            userInfo={userInfo}
            onUpdateRequirementStatus={handleUpdateRequirementStatus}
            onRaiseRequirement={handleRaiseRequirement}
            linkedTodos={todos.filter(t => t.orderId?._id === selectedOrderId || t.orderId === selectedOrderId)}
            onTodoStatusChange={handleTodoStatusChange}
            isClockedIn={isClockedIn}
            onTaskStatusChange={handleTaskStatusChange}
            onUpdateSubtask={handleUpdateSubtask}
          />
        );
      case 'tasks':
        return (
          <TaskManagementModule
            orders={orders}
            userInfo={userInfo}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onTaskStatusChange={handleTaskStatusChange}
            onUpdateSubtask={handleUpdateSubtask}
            activeTaskSession={activeTaskSession}
            activeTaskElapsedSeconds={activeTaskElapsedSeconds}
            onStartTask={startTaskSession}
            onPauseTask={pauseTaskSession}
            onCompleteTask={completeTaskSession}
            isClockedIn={isClockedIn}
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
        return (
          <RequirementsModule
            selectedOrder={selectedOrder}
            onUpdateRequirementStatus={handleUpdateRequirementStatus}
            onRaiseRequirement={handleRaiseRequirement}
          />
        );
      case 'support':
        return <SupportModule tickets={tickets} />;
      case 'commercials':
        return <CommercialsModule selectedOrder={selectedOrder} />;
      case 'finance':
        return <FinanceModule token={userInfo?.token} />;
      case 'notifications':
        return (
          <NotificationsFeed 
            notifications={notifications}
            onMarkRead={markRead}
            onMarkAllRead={markAllRead}
            onClickAction={(notif) => {
              if (notif.type === 'Ticket') {
                setActiveTab('support');
              } else {
                setActiveTab('queue');
              }
            }}
          />
        );
      case 'security':
        return <SecurityModule />;
      case 'hrms':
        return <HRMSModule role={userInfo?.role} />;
      default:
        return <DashboardOverviewModule userInfo={userInfo} orders={orders} onOpenOrder={openOrderInProcessing} />;
    }
  };

  return (
    <div className="flex h-screen bg-gradient-to-br from-slate-100 via-blue-50 to-indigo-100 font-sans text-slate-800 overflow-hidden">
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
        <div className="flex-1 overflow-y-auto p-4 sm:p-6">{renderActiveModule()}</div>
      </main>
      <InAppBanner 
        activeNotification={activeBannerNotification}
        onDismiss={() => setActiveBannerNotification(null)}
        onClickAction={() => setActiveTab('notifications')}
      />
    </div>
  );
};

export default EmployeeApp;
