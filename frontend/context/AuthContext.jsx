import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(() => {
        try {
            const saved = localStorage.getItem('userInfo');
            return saved ? JSON.parse(saved) : null;
        } catch {
            return null;
        }
    });
    const [loading, setLoading] = useState(true);

    const checkUserLoggedIn = async () => {
        const token = localStorage.getItem('token');
        if (token) {
            try {
                const config = {
                    headers: { Authorization: `Bearer ${token}` }
                };
                const { data } = await axios.get('/api/auth/profile', config);
                const fullUser = { ...data, token };
                setUser(fullUser);
                localStorage.setItem('userInfo', JSON.stringify(fullUser));
            } catch (error) {
                if (error.response?.status === 401 || error.response?.status === 403) {
                    console.error("Session expired or invalid token");
                    localStorage.removeItem('token');
                    localStorage.removeItem('userInfo');
                    setUser(null);
                }
            }
        } else {
            setUser(null);
        }
        setLoading(false);
    };

    useEffect(() => {
        checkUserLoggedIn();
    }, []);

    const login = async (email, password) => {
        const { data } = await axios.post('/api/auth/login', { email, password });
        localStorage.setItem('token', data.token);
        localStorage.setItem('userInfo', JSON.stringify(data));
        setUser(data);
        return data; // Return user data for redirect logic
    };

    const googleLogin = async (tokenData) => {
        let payload = {};
        if (typeof tokenData === 'string') {
            payload = { credential: tokenData, idToken: tokenData };
        } else if (tokenData?.access_token) {
            payload = { accessToken: tokenData.access_token };
        } else if (tokenData?.credential) {
            payload = { credential: tokenData.credential, idToken: tokenData.credential };
        } else {
            payload = { accessToken: tokenData?.id_token || tokenData?.access_token };
        }
        const { data } = await axios.post('/api/auth/google', payload);
        localStorage.setItem('token', data.token);
        localStorage.setItem('userInfo', JSON.stringify(data));
        setUser(data);
        return data;
    };

    const register = async (name, email, phone, password, role) => {
        try {
            const config = { headers: { 'Content-Type': 'application/json' } };
            const { data } = await axios.post('/api/auth/register', { name, email, phone, password, role }, config);
            localStorage.setItem('token', data.token);
            localStorage.setItem('userInfo', JSON.stringify(data));
            setUser(data);
            return data;
        } catch (error) {
            console.error("Registration failed:", error.response ? error.response.data : error.message);
            throw error; // Re-throw to allow calling component to handle
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('userInfo');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, loading, login, googleLogin, register, logout }}>
            {children}
        </AuthContext.Provider>
    );
};
