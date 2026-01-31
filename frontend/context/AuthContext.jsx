import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    const checkUserLoggedIn = async () => {
        const token = localStorage.getItem('token');
        if (token) {
            try {
                const config = {
                    headers: { Authorization: `Bearer ${token}` }
                };
                const { data } = await axios.get('http://localhost:5000/api/auth/profile', config);
                setUser({ ...data, token });
            } catch (error) {
                console.error("Session expired or invalid token");
                localStorage.removeItem('token');
                setUser(null);
            }
        }
        setLoading(false);
    };

    useEffect(() => {
        checkUserLoggedIn();
    }, []);

    const login = async (email, password) => {
        const { data } = await axios.post('http://localhost:5000/api/auth/login', { email, password });
        localStorage.setItem('token', data.token);
        setUser(data);
        return data; // Return user data for redirect logic
    };

    const register = async (name, email, phone, password) => {
        const { data } = await axios.post('http://localhost:5000/api/auth/register', { name, email, phone, password });
        localStorage.setItem('token', data.token);
        setUser(data);
    };

    const logout = () => {
        localStorage.removeItem('token');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, loading, login, register, logout }}>
            {children}
        </AuthContext.Provider>
    );
};
