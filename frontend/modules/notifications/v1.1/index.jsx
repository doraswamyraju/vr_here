import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import NotificationCard from './components/NotificationCard';
import InAppBanner from './components/InAppBanner';
import NotificationsFeed from './components/NotificationsFeed';
import { auth, db } from '../../config/firebase';
import { signInWithCustomToken } from 'firebase/auth';
import { collection, query, orderBy, onSnapshot, doc, updateDoc } from 'firebase/firestore';

export { NotificationCard, InAppBanner, NotificationsFeed };

// JWT parsing utility to extract userId
const parseJwt = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch (e) {
    return null;
  }
};

// Retrieve custom token from localStorage
const getFirebaseToken = () => {
  try {
    const stored = localStorage.getItem('userInfo');
    if (stored) {
      const parsed = JSON.parse(stored);
      return parsed.firebaseCustomToken;
    }
  } catch (e) {
    console.error('Failed to parse userInfo for firebase token:', e.message);
  }
  return null;
};

/**
 * Custom React hook to manage notification synchronization, in-app banner alerts,
 * and read/unread status updates. Uses real-time Firestore listeners with a REST polling fallback.
 */
export const useNotifications = (token) => {
  const [notifications, setNotifications] = useState([]);
  const [activeBannerNotification, setActiveBannerNotification] = useState(null);
  const [loading, setLoading] = useState(false);
  const [useFirestore, setUseFirestore] = useState(false);
  const prevNotificationsRef = useRef([]);

  const config = useCallback(() => {
    return token ? { headers: { Authorization: `Bearer ${token}` } } : null;
  }, [token]);

  // Sync notifications from Backend REST endpoint (Fallback mode)
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
        const newUnreads = fetched.filter(
          item => !item.isRead && !oldList.some(oldItem => oldItem._id === item._id)
        );

        if (newUnreads.length > 0) {
          setActiveBannerNotification(newUnreads[0]);
        }
      }

      prevNotificationsRef.current = fetched;
    } catch (error) {
      console.error('Failed to sync notifications via REST:', error.message);
    } finally {
      setLoading(false);
    }
  }, [config]);

  // Authenticate with Firebase Custom Token
  useEffect(() => {
    const customToken = getFirebaseToken();
    if (!customToken) {
      setUseFirestore(false);
      return;
    }

    if (customToken.startsWith('mock-')) {
      console.log('Firebase Custom Token is a simulated developer token. Falling back to REST polling.');
      setUseFirestore(false);
      return;
    }

    signInWithCustomToken(auth, customToken)
      .then(() => {
        console.log('Authenticated to Firebase Auth via Custom Token.');
        setUseFirestore(true);
      })
      .catch((err) => {
        console.warn('Firebase Custom Token sign-in failed. Using REST polling fallback:', err.message);
        setUseFirestore(false);
      });
  }, [token]);

  // Real-time synchronization selection
  useEffect(() => {
    if (!token) return;

    if (useFirestore) {
      const decoded = parseJwt(token);
      const userId = decoded?.id;
      if (!userId) return;

      console.log(`Subscribing to real-time Firestore notifications for User [${userId}]`);
      const q = query(
        collection(db, 'users', userId, 'notifications'),
        orderBy('createdAt', 'desc')
      );

      const unsubscribe = onSnapshot(q, (snapshot) => {
        const fetched = [];
        snapshot.forEach((doc) => {
          fetched.push({ _id: doc.id, ...doc.data() });
        });
        setNotifications(fetched);

        // Detect brand-new unread notifications to trigger floating heads-up banner
        const oldList = prevNotificationsRef.current;
        if (oldList.length > 0 && fetched.length > 0) {
          const newUnreads = fetched.filter(
            item => !item.isRead && !oldList.some(oldItem => oldItem._id === item._id)
          );

          if (newUnreads.length > 0) {
            setActiveBannerNotification(newUnreads[0]);
          }
        }

        prevNotificationsRef.current = fetched;
      }, (error) => {
        console.error('Firestore notifications subscription error:', error.message);
        setUseFirestore(false); // fallback to REST polling on subscription failure
      });

      return () => unsubscribe();
    } else {
      // REST polling sync (runs every 15 seconds)
      fetchNotifications();
      const interval = setInterval(() => {
        fetchNotifications();
      }, 15000);

      return () => clearInterval(interval);
    }
  }, [token, useFirestore, fetchNotifications]);

  // Mark single notification as read
  const markRead = useCallback(async (id) => {
    const apiConfig = config();
    if (!apiConfig) return;

    if (useFirestore) {
      const decoded = parseJwt(token);
      const userId = decoded?.id;
      if (userId) {
        try {
          const docRef = doc(db, 'users', userId, 'notifications', id);
          await updateDoc(docRef, { isRead: true });
          console.log(`Marked notification ${id} as read in Firestore.`);
        } catch (err) {
          console.error(`Failed to update Firestore notification ${id}:`, err.message);
        }
      }
    }

    try {
      await axios.put(`/api/notifications/${id}/read`, {}, apiConfig);
      setNotifications(prev => prev.map(notif => 
        notif._id === id ? { ...notif, isRead: true } : notif
      ));
      prevNotificationsRef.current = prevNotificationsRef.current.map(notif => 
        notif._id === id ? { ...notif, isRead: true } : notif
      );
    } catch (error) {
      console.error(`Failed to sync read status for notification [${id}] with MongoDB:`, error.message);
    }
  }, [config, token, useFirestore]);

  // Mark all notifications as read
  const markAllRead = useCallback(async () => {
    const apiConfig = config();
    if (!apiConfig) return;

    if (useFirestore) {
      const decoded = parseJwt(token);
      const userId = decoded?.id;
      if (userId) {
        try {
          const unreads = notifications.filter(n => !n.isRead);
          for (const item of unreads) {
            const docRef = doc(db, 'users', userId, 'notifications', item._id);
            updateDoc(docRef, { isRead: true }).catch(() => {});
          }
          console.log('Marked all notifications as read in Firestore.');
        } catch (err) {
          console.error('Failed to bulk update Firestore notifications:', err.message);
        }
      }
    }

    try {
      await axios.put('/api/notifications/readall', {}, apiConfig);
      setNotifications(prev => prev.map(notif => ({ ...notif, isRead: true })));
      prevNotificationsRef.current = prevNotificationsRef.current.map(notif => ({ ...notif, isRead: true }));
    } catch (error) {
      console.error('Failed to sync bulk read status with MongoDB:', error.message);
    }
  }, [config, token, useFirestore, notifications]);

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

