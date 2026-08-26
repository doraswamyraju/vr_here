import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { MapPin, Plus, Trash2, Edit3, Save, CheckCircle2, XCircle, Search, RefreshCw, Loader2 } from 'lucide-react';

const CityManager = ({ token }) => {
    const [cities, setCities] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [message, setMessage] = useState({ text: '', type: '' });

    const [modalOpen, setModalOpen] = useState(false);
    const [editingCity, setEditingCity] = useState(null);
    const [form, setForm] = useState({
        name: '',
        slug: '',
        state: '',
        district: '',
        landmark: '',
        pincode: '',
        phone: '',
        isActive: true
    });

    const authConfig = { headers: { Authorization: `Bearer ${token}` } };

    const fetchCities = async () => {
        setIsLoading(true);
        try {
            const { data } = await axios.get('/api/cities?all=true', authConfig);
            setCities(data || []);
        } catch (err) {
            console.error('Failed to load cities', err);
            setMessage({ text: 'Failed to load cities.', type: 'error' });
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchCities();
    }, []);

    const handleOpenModal = (city = null) => {
        if (city) {
            setEditingCity(city);
            setForm({
                name: city.name,
                slug: city.slug,
                state: city.state,
                district: city.district || '',
                landmark: city.landmark || '',
                pincode: city.pincode || '',
                phone: city.phone || '',
                isActive: city.isActive !== undefined ? city.isActive : true
            });
        } else {
            setEditingCity(null);
            setForm({
                name: '',
                slug: '',
                state: 'Andhra Pradesh',
                district: '',
                landmark: '',
                pincode: '',
                phone: '',
                isActive: true
            });
        }
        setModalOpen(true);
    };

    const handleSaveCity = async (e) => {
        e.preventDefault();
        setIsSaving(true);
        setMessage({ text: '', type: '' });

        try {
            if (editingCity) {
                await axios.put(`/api/cities/${editingCity._id}`, form, authConfig);
                setMessage({ text: `City "${form.name}" updated successfully!`, type: 'success' });
            } else {
                await axios.post('/api/cities', form, authConfig);
                setMessage({ text: `City "${form.name}" created successfully!`, type: 'success' });
            }
            setModalOpen(false);
            fetchCities();
        } catch (err) {
            console.error('Save city error', err);
            setMessage({ text: err.response?.data?.message || 'Error saving city', type: 'error' });
        } finally {
            setIsSaving(false);
        }
    };

    const handleDeleteCity = async (id, name) => {
        if (!window.confirm(`Are you sure you want to delete city "${name}"?`)) return;
        try {
            await axios.delete(`/api/cities/${id}`, authConfig);
            setMessage({ text: `City "${name}" deleted.`, type: 'success' });
            fetchCities();
        } catch (err) {
            console.error('Delete city error', err);
            setMessage({ text: 'Failed to delete city.', type: 'error' });
        }
    };

    const filteredCities = cities.filter(c =>
        c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.state.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (c.slug && c.slug.toLowerCase().includes(searchTerm.toLowerCase()))
    );

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 bg-white p-5 rounded-2xl border border-slate-200/80 shadow-sm">
                <div>
                    <h2 className="text-xl font-bold text-slate-800 flex items-center gap-2">
                        <MapPin className="w-5 h-5 text-indigo-600" />
                        Master City Database
                    </h2>
                    <p className="text-sm text-slate-500 mt-1">
                        Cities added here automatically generate localized SEO landing pages for all enabled services.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={fetchCities}
                        className="p-2 text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition"
                        title="Refresh list"
                    >
                        <RefreshCw className={`w-5 h-5 ${isLoading ? 'animate-spin' : ''}`} />
                    </button>
                    <button
                        onClick={() => handleOpenModal()}
                        className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold shadow-md shadow-indigo-200 hover:bg-indigo-700 transition"
                    >
                        <Plus className="w-4 h-4" />
                        Add New City
                    </button>
                </div>
            </div>

            {message.text && (
                <div className={`p-4 rounded-xl text-sm font-medium ${message.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-red-50 text-red-800 border border-red-200'}`}>
                    {message.text}
                </div>
            )}

            {/* Search Filter */}
            <div className="relative max-w-md">
                <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
                <input
                    type="text"
                    placeholder="Search city by name, state or slug..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-200 bg-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                />
            </div>

            {/* Cities Table */}
            {isLoading ? (
                <div className="flex justify-center items-center py-16 bg-white rounded-2xl border border-slate-200">
                    <Loader2 className="w-8 h-8 text-indigo-600 animate-spin" />
                </div>
            ) : filteredCities.length === 0 ? (
                <div className="text-center py-12 bg-white rounded-2xl border border-slate-200 text-slate-500 text-sm">
                    No cities found. Click <strong>"Add New City"</strong> to get started.
                </div>
            ) : (
                <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm text-slate-600">
                            <thead className="bg-slate-50 border-b border-slate-200 text-slate-700 font-semibold uppercase text-xs">
                                <tr>
                                    <th className="py-3.5 px-4">City</th>
                                    <th className="py-3.5 px-4">Slug</th>
                                    <th className="py-3.5 px-4">State</th>
                                    <th className="py-3.5 px-4">Landmark / Office</th>
                                    <th className="py-3.5 px-4">Pincode</th>
                                    <th className="py-3.5 px-4">Status</th>
                                    <th className="py-3.5 px-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filteredCities.map((city) => (
                                    <tr key={city._id} className="hover:bg-slate-50/80 transition">
                                        <td className="py-3.5 px-4 font-semibold text-slate-900 flex items-center gap-2">
                                            <MapPin className="w-4 h-4 text-indigo-500 shrink-0" />
                                            {city.name}
                                        </td>
                                        <td className="py-3.5 px-4 text-slate-500 font-mono text-xs">
                                            {city.slug}
                                        </td>
                                        <td className="py-3.5 px-4 font-medium text-slate-700">
                                            {city.state}
                                        </td>
                                        <td className="py-3.5 px-4 text-slate-500">
                                            {city.landmark || '—'}
                                        </td>
                                        <td className="py-3.5 px-4 text-slate-500 font-mono text-xs">
                                            {city.pincode || '—'}
                                        </td>
                                        <td className="py-3.5 px-4">
                                            {city.isActive ? (
                                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                                    <CheckCircle2 className="w-3.5 h-3.5" /> Active
                                                </span>
                                            ) : (
                                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200">
                                                    <XCircle className="w-3.5 h-3.5" /> Inactive
                                                </span>
                                            )}
                                        </td>
                                        <td className="py-3.5 px-4 text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <button
                                                    onClick={() => handleOpenModal(city)}
                                                    className="p-1.5 text-slate-600 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition"
                                                    title="Edit City"
                                                >
                                                    <Edit3 className="w-4 h-4" />
                                                </button>
                                                <button
                                                    onClick={() => handleDeleteCity(city._id, city.name)}
                                                    className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition"
                                                    title="Delete City"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* City Modal */}
            {modalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
                    <div className="bg-white rounded-2xl shadow-xl border border-slate-200 max-w-lg w-full p-6 space-y-5">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                            <h3 className="text-lg font-bold text-slate-800 flex items-center gap-2">
                                <MapPin className="w-5 h-5 text-indigo-600" />
                                {editingCity ? 'Edit City' : 'Add New City'}
                            </h3>
                            <button onClick={() => setModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                                ✕
                            </button>
                        </div>

                        <form onSubmit={handleSaveCity} className="space-y-4 text-sm">
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">City Name *</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="e.g. Tirupati"
                                        value={form.name}
                                        onChange={(e) => {
                                            const val = e.target.value;
                                            setForm(prev => ({
                                                ...prev,
                                                name: val,
                                                slug: val.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
                                            }));
                                        }}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                                    />
                                </div>
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">URL Slug</label>
                                    <input
                                        type="text"
                                        placeholder="e.g. tirupati"
                                        value={form.slug}
                                        onChange={(e) => setForm(prev => ({ ...prev, slug: e.target.value }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 font-mono text-xs focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                                    />
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">State *</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="e.g. Andhra Pradesh"
                                        value={form.state}
                                        onChange={(e) => setForm(prev => ({ ...prev, state: e.target.value }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                                    />
                                </div>
                                <div>
                                    <label className="block font-semibold text-slate-700 mb-1">Pincode</label>
                                    <input
                                        type="text"
                                        placeholder="e.g. 517501"
                                        value={form.pincode}
                                        onChange={(e) => setForm(prev => ({ ...prev, pincode: e.target.value }))}
                                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 font-mono text-xs focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block font-semibold text-slate-700 mb-1">Local Landmark / Office Address</label>
                                <input
                                    type="text"
                                    placeholder="e.g. Air Bypass Road, Tirupati"
                                    value={form.landmark}
                                    onChange={(e) => setForm(prev => ({ ...prev, landmark: e.target.value }))}
                                    className="w-full px-3.5 py-2 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                                />
                            </div>

                            <div className="flex items-center gap-2 pt-2">
                                <input
                                    type="checkbox"
                                    id="cityIsActive"
                                    checked={form.isActive}
                                    onChange={(e) => setForm(prev => ({ ...prev, isActive: e.target.checked }))}
                                    className="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500"
                                />
                                <label htmlFor="cityIsActive" className="text-slate-700 font-medium cursor-pointer">
                                    Active for Auto-Generation
                                </label>
                            </div>

                            <div className="flex justify-end gap-3 pt-4 border-t border-slate-100">
                                <button
                                    type="button"
                                    onClick={() => setModalOpen(false)}
                                    className="px-4 py-2 rounded-xl text-slate-600 hover:bg-slate-100 font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSaving}
                                    className="flex items-center gap-2 px-5 py-2 bg-indigo-600 text-white rounded-xl font-semibold shadow-md shadow-indigo-200 hover:bg-indigo-700 transition disabled:opacity-50"
                                >
                                    {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                                    Save City
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CityManager;
