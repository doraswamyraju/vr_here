import axios from 'axios';

/**
 * Service Configuration API integrations
 */

const getAuthHeaders = () => {
    const token = localStorage.getItem('token') || (JSON.parse(localStorage.getItem('userInfo'))?.token);
    return token ? { Authorization: `Bearer ${token}` } : {};
};

export const fetchServicePageConfig = async (pageId) => {
    const response = await axios.get(`/api/service-pages/${pageId}`);
    return response.data;
};

export const updateServicePageConfig = async (pageId, configData) => {
    const response = await axios.post(`/api/service-pages/${pageId}`, configData, {
        headers: getAuthHeaders()
    });
    return response.data;
};

export const fetchAllServicePages = async () => {
    const response = await axios.get('/api/service-pages');
    return response.data;
};
