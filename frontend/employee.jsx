import React, { useCallback, useEffect, useMemo, useState } from 'react';
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

const EmployeeApp = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [userInfo, setUserInfo] = useState(null);
  const [orders, setOrders] = useState([]);
  const [selectedOrderId, setSelectedOrderId] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [tickets, setTickets] = useState([]);
  const [isUploading, setIsUploading] = useState(false);

  const navigate = useNavigate();

  const authConfig = useMemo(() => (
    userInfo?.token
      ? { headers: { Authorization: `Bearer ${userInfo.token}` } }
      : null
  ), [userInfo]);

  const selectedOrder = useMemo(
    () => orders.find((order) => order._id === selectedOrderId) || null,
    [orders, selectedOrderId]
  );

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

  const refreshAll = () => {
    fetchOrders();
    fetchExtras();
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

  const handleToggleSubtask = async (orderId, taskId, subtaskId) => {
    if (!authConfig) return;

    const order = orders.find((item) => item._id === orderId);
    const task = order?.tasks?.find((item) => item._id === taskId);
    if (!task) return;

    const updatedSubtasks = (task.subtasks || []).map((subtask) => (
      subtask._id === subtaskId
        ? { ...subtask, isCompleted: !subtask.isCompleted }
        : subtask
    ));

    try {
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}`, { subtasks: updatedSubtasks }, authConfig);
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
            onToggleSubtask={handleToggleSubtask}
          />
        );
      case 'time':
        return <TimeTrackingModule selectedOrder={selectedOrder} onLogTime={handleLogTime} />;
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
        <EmployeeTopbar activeTab={activeTab} userInfo={userInfo} onRefresh={refreshAll} />
        <div className="flex-1 overflow-y-auto p-6 md:p-8">{renderActiveModule()}</div>
      </main>
    </div>
  );
};

export default EmployeeApp;
