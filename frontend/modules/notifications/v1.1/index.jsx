import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import NotificationCard from './components/NotificationCard';
import InAppBanner from './components/InAppBanner';
import NotificationsFeed from './components/NotificationsFeed';

export { NotificationCard, InAppBanner, NotificationsFeed };

/**
 * Custom React hook to manage notification synchronization, in-app banner alerts,
 * and read/unread status updates.
 */
export const useNotifications = (token) => {
  const [notifications, setNotifications] = useState([]);
  const [activeBannerNotification, setActiveBannerNotification] = useState(null);
  const [loading, setLoading] = useState(false);
  const prevNotificationsRef = useRef([]);

  const config = useCallback(() => {
    return token ? { headers: { Authorization: `Bearer ${token}` } } : null;
  }, [token]);

  // Sync notifications from Backend REST endpoint
  const fetchNotifications = useCallback(async () => {
    const apiConfig = config();
    if (!apiConfig) return;

    try {
      setLoading(true);
      const { data } = await axios.get('/api/notifications', apiConfig);
      
      const fetched = Array.isArray(data) ? data : [];
      setNotifications(fetched);

      // Detect brand-new unread notifications to trigger floating heads-up banner
      const oldList = prevNotificationsRef.current;
      if (oldList.length > 0 && fetched.length > 0) {
        // Find if there are unread notifications in fetched that weren't in oldList
        const newUnreads = fetched.filter(
          item => !item.isRead && !oldList.some(oldItem => oldItem._id === item._id)
        );

        if (newUnreads.length > 0) {
          // Trigger banner for the most recent one
          setActiveBannerNotification(newUnreads[0]);
        }
      }

      // Update ref list
      prevNotificationsRef.current = fetched;
    } catch (error) {
      console.error('Failed to sync notifications:', error.message);
    } finally {
      setLoading(false);
    }
  }, [config]);

  // Mark single notification as read
  const markRead = useCallback(async (id) => {
    const apiConfig = config();
    if (!apiConfig) return;

    try {
      await axios.put(`/api/notifications/${id}/read`, {}, apiConfig);
      
      // Update local state dynamically
      setNotifications(prev => prev.map(notif => 
        notif._id === id ? { ...notif, isRead: true } : notif
      ));
      
      // Update ref list
      prevNotificationsRef.current = prevNotificationsRef.current.map(notif => 
        notif._id === id ? { ...notif, isRead: true } : notif
      );
    } catch (error) {
      console.error(`Failed to mark notification [${id}] as read:`, error.message);
    }
  }, [config]);

  // Mark all notifications as read
  const markAllRead = useCallback(async () => {
    const apiConfig = config();
    if (!apiConfig) return;

    try {
      await axios.put('/api/notifications/readall', {}, apiConfig);
      
      // Update local state dynamically
      setNotifications(prev => prev.map(notif => ({ ...notif, isRead: true })));
      
      // Update ref list
      prevNotificationsRef.current = prevNotificationsRef.current.map(notif => ({ ...notif, isRead: true }));
    } catch (error) {
      console.error('Failed to mark all notifications as read:', error.message);
    }
  }, [config]);

  // Set up periodic sync (polling every 15 seconds)
  useEffect(() => {
    fetchNotifications();

    const interval = setInterval(() => {
      fetchNotifications();
    }, 15000);

    return () => clearInterval(interval);
  }, [fetchNotifications]);

  const unreadCount = notifications.filter(n => !n.isRead).length;

  return {
    notifications,
    activeBannerNotification,
    setActiveBannerNotification,
    unreadCount,
    loading,
    fetchNotifications,
    markRead,
    markAllRead
  };
};
