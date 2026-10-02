import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import {
  Sparkles,
  Plus,
  Search,
  Edit2,
  Trash2,
  Eye,
  CheckCircle2,
  XCircle,
  Tag,
  Percent,
  Calendar,
  Layers,
  ArrowRight,
  RefreshCw,
  X,
  ExternalLink,
  Image as ImageIcon
} from 'lucide-react';

const INITIAL_OFFER_FORM = {
  title: '',
  subtitle: '',
  badgeTag: 'LIMITED TIME',
  badgeColor: '#DC2626',
  bannerImageUrl: '',
  targetServiceKey: '',
  targetUrl: '',
  discountAmount: 0,
  originalPrice: 0,
  discountedPrice: 0,
  eligibilityText: 'Tap to view eligibility & apply',
  ctaText: 'Register Today →',
  isActive: true,
  priority: 0,
  validUntil: ''
};

const DEFAULT_SAMPLE_OFFERS = [
  {
    title: 'ROC CCFS-2026 Amnesty Scheme',
    subtitle: '100% Late Filing Penalty Waiver for pending MCA returns. Clear years of default with zero additional fees.',
    badgeTag: 'LIMITED PERIOD',
    badgeColor: '#F43F5E',
    bannerImageUrl: 'https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=800&auto=format&fit=crop&q=80',
    targetServiceKey: 'compliance-scheme-2026',
    targetUrl: 'https://vrhere.in/compliance-scheme-2026',
    discountAmount: 10000,
    originalPrice: 15000,
    discountedPrice: 5000,
    eligibilityText: 'Valid for active and defaulting Private Limited / OPC companies.',
    ctaText: 'Avail Scheme →',
    isActive: true,
    priority: 10
  },
  {
    title: 'Startup India & 80-IAC 3-Year Exemption',
    subtitle: 'Get 100% Income Tax Exemption for 3 consecutive years with DPIIT Recognition & IMB Certification.',
    badgeTag: 'DPIIT APPROVED',
    badgeColor: '#10B981',
    bannerImageUrl: 'https://images.unsplash.com/photo-1519389950473-47ba0277781c?w=800&auto=format&fit=crop&q=80',
    targetServiceKey: 'startup-india',
    targetUrl: 'https://vrhere.in/startup-india',
    discountAmount: 5000,
    originalPrice: 14999,
    discountedPrice: 9999,
    eligibilityText: 'Available for DPIIT registered Private Limited & LLP startups.',
    ctaText: 'Apply Now →',
    isActive: true,
    priority: 9
  },
  {
    title: 'Free GST + MSME with Pvt Ltd',
    subtitle: 'Complete incorporation with DIN, DSC, MOA, AOA, PAN, TAN, GSTIN & MSME Udyam registration included.',
    badgeTag: 'SAVE ₹4,999',
    badgeColor: '#6366F1',
    bannerImageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=800&auto=format&fit=crop&q=80',
    targetServiceKey: 'pvt-ltd-registration',
    targetUrl: 'https://vrhere.in/pvt-ltd-registration',
    discountAmount: 4999,
    originalPrice: 12999,
    discountedPrice: 7999,
    eligibilityText: 'Valid for new enterprise registrations initiated this month.',
    ctaText: 'Register Today →',
    isActive: true,
    priority: 8
  },
  {
    title: 'Fast-Track ISO 9001 / 27001 Certification',
    subtitle: 'Globally recognized IAF/UAF accredited certification delivered in 3 working days for tender eligibility.',
    badgeTag: '3-DAY DISPATCH',
    badgeColor: '#F59E0B',
    bannerImageUrl: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=800&auto=format&fit=crop&q=80',
    targetServiceKey: 'iso-certification',
    targetUrl: '/services',
    discountAmount: 3000,
    originalPrice: 9999,
    discountedPrice: 6999,
    eligibilityText: 'Open to IT, manufacturing, healthcare, and service businesses.',
    ctaText: 'Get Certified →',
    isActive: true,
    priority: 7
  }
];

const PRESET_BADGE_COLORS = [
  { name: 'Red Crimson', color: '#DC2626' },
  { name: 'Indigo Royal', color: '#4F46E5' },
  { name: 'Emerald Green', color: '#059669' },
  { name: 'Amber Gold', color: '#D97706' },
  { name: 'Purple Violet', color: '#7C3AED' },
  { name: 'Pink Rose', color: '#DB2777' }
];

export default function AdminOffersView({ token }) {
  const [offers, setOffers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const [modalOpen, setModalOpen] = useState(false);
  const [previewOffer, setPreviewOffer] = useState(null);
  const [editingOfferId, setEditingOfferId] = useState(null);
  const [formData, setFormData] = useState(INITIAL_OFFER_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [actionMessage, setActionMessage] = useState({ text: '', type: '' });

  const authHeader = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const showNotification = (text, type = 'success') => {
    setActionMessage({ text, type });
    setTimeout(() => setActionMessage({ text: '', type: '' }), 4000);
  };

  const fetchOffers = async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/offers/admin/all', authHeader);
      setOffers(res.data || []);
    } catch (err) {
      console.error('Failed to load offers:', err);
      showNotification(err.response?.data?.message || 'Failed to fetch offers', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOffers();
  }, [authHeader]);

  const handleOpenCreate = () => {
    setEditingOfferId(null);
    setFormData(INITIAL_OFFER_FORM);
    setModalOpen(true);
  };

  const handleOpenEdit = (offer) => {
    setEditingOfferId(offer._id);
    setFormData({
      title: offer.title || '',
      subtitle: offer.subtitle || '',
      badgeTag: offer.badgeTag || 'LIMITED TIME',
      badgeColor: offer.badgeColor || '#DC2626',
      bannerImageUrl: offer.bannerImageUrl || '',
      targetServiceKey: offer.targetServiceKey || '',
      targetUrl: offer.targetUrl || '',
      discountAmount: offer.discountAmount || 0,
      originalPrice: offer.originalPrice || 0,
      discountedPrice: offer.discountedPrice || 0,
      eligibilityText: offer.eligibilityText || 'Tap to view eligibility & apply',
      ctaText: offer.ctaText || 'Register Today →',
      isActive: offer.isActive !== undefined ? offer.isActive : true,
      priority: offer.priority || 0,
      validUntil: offer.validUntil ? new Date(offer.validUntil).toISOString().split('T')[0] : ''
    });
    setModalOpen(true);
  };

  const handlePriceCalculations = (field, val) => {
    const num = Number(val) || 0;
    setFormData(prev => {
      const updated = { ...prev, [field]: num };
      if (field === 'originalPrice') {
        if (updated.discountedPrice > 0 && num > updated.discountedPrice) {
          updated.discountAmount = num - updated.discountedPrice;
        }
      } else if (field === 'discountedPrice') {
        if (updated.originalPrice > 0 && updated.originalPrice > num) {
          updated.discountAmount = updated.originalPrice - num;
        }
      }
      return updated;
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.title.trim() || !formData.subtitle.trim()) {
      showNotification('Title and subtitle are required.', 'error');
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        ...formData,
        validUntil: formData.validUntil ? new Date(formData.validUntil) : null
      };

      if (editingOfferId) {
        await axios.put(`/api/offers/${editingOfferId}`, payload, authHeader);
        showNotification('Offer banner updated successfully!');
      } else {
        await axios.post('/api/offers', payload, authHeader);
        showNotification('Offer scheme created and published!');
      }
      setModalOpen(false);
      fetchOffers();
    } catch (err) {
      console.error('Submit failed:', err);
      showNotification(err.response?.data?.message || 'Operation failed', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (offer) => {
    if (!window.confirm(`Are you sure you want to delete scheme "${offer.title}"?`)) return;
    try {
      await axios.delete(`/api/offers/${offer._id}`, authHeader);
      showNotification('Offer deleted successfully');
      fetchOffers();
    } catch (err) {
      console.error('Delete failed:', err);
      showNotification(err.response?.data?.message || 'Delete failed', 'error');
    }
  };

  const handleToggleActive = async (offer) => {
    try {
      await axios.put(`/api/offers/${offer._id}`, { isActive: !offer.isActive }, authHeader);
      showNotification(`Scheme ${!offer.isActive ? 'activated' : 'deactivated'}`);
      fetchOffers();
    } catch (err) {
      console.error('Toggle status failed:', err);
      showNotification('Failed to update status', 'error');
    }
  };

  const handleSeedDefaults = async () => {
    if (!window.confirm('Seed default sample promotional banners & schemes?')) return;
    try {
      setLoading(true);
      for (const o of DEFAULT_SAMPLE_OFFERS) {
        await axios.post('/api/offers', o, authHeader);
      }
      showNotification('Default schemes seeded successfully!');
      fetchOffers();
    } catch (err) {
      console.error('Seed failed:', err);
      showNotification('Failed to seed defaults', 'error');
    } finally {
      setLoading(false);
    }
  };

  const filteredOffers = useMemo(() => {
    return offers.filter(o => {
      const matchSearch = o.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          o.subtitle.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          (o.badgeTag && o.badgeTag.toLowerCase().includes(searchQuery.toLowerCase())) ||
                          (o.targetServiceKey && o.targetServiceKey.toLowerCase().includes(searchQuery.toLowerCase()));
      const matchStatus = statusFilter === 'All' ||
                          (statusFilter === 'Active' && o.isActive) ||
                          (statusFilter === 'Inactive' && !o.isActive);
      return matchSearch && matchStatus;
    });
  }, [offers, searchQuery, statusFilter]);

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {actionMessage.text && (
        <div className={`p-4 rounded-2xl flex items-center justify-between shadow-lg text-sm font-bold animate-in fade-in duration-200 ${
          actionMessage.type === 'error' ? 'bg-rose-500 text-white shadow-rose-500/20' : 'bg-emerald-600 text-white shadow-emerald-600/20'
        }`}>
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage({ text: '', type: '' })} className="p-1 hover:opacity-80">
            <X size={16} />
          </button>
        </div>
      )}

      {/* Hero Header */}
      <div className="rounded-3xl bg-gradient-to-r from-slate-900 via-rose-950 to-indigo-950 p-6 sm:p-8 text-white relative overflow-hidden shadow-xl">
        <div className="absolute right-0 top-0 p-8 opacity-10 pointer-events-none">
          <Sparkles size={160} />
        </div>
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 text-rose-300 text-[10px] font-black uppercase tracking-widest backdrop-blur-md mb-3">
              <Tag size={12} /> Promotional Schemes & Banners Studio
            </div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight">Promotional Offers & Schemes</h1>
            <p className="text-slate-300 text-sm mt-1 max-w-xl">
              Configure dynamic seasonal discounts, high-res visual banner creatives, and service vouchers. Synchronized live to Web, Android, and iOS carousels.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {offers.length === 0 && (
              <button
                onClick={handleSeedDefaults}
                className="px-4 py-3 rounded-2xl bg-white/10 hover:bg-white/20 text-white text-xs font-black uppercase tracking-wider transition backdrop-blur-md flex items-center gap-2"
              >
                <Sparkles size={16} className="text-rose-300" /> Seed Sample Offers
              </button>
            )}
            <button
              onClick={handleOpenCreate}
              className="px-5 py-3 rounded-2xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-black uppercase tracking-wider transition shadow-lg shadow-rose-600/30 flex items-center gap-2 active:scale-95"
            >
              <Plus size={18} /> New Offer Scheme
            </button>
          </div>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Schemes', val: offers.length, color: 'text-rose-600', bg: 'bg-rose-50' },
          { label: 'Active in Carousels', val: offers.filter(o => o.isActive).length, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Max Discount', val: offers.length > 0 ? `₹${Math.max(...offers.map(o => o.discountAmount || 0)).toLocaleString()}` : '₹0', color: 'text-indigo-600', bg: 'bg-indigo-50' },
          { label: 'Inactive / Paused', val: offers.filter(o => !o.isActive).length, color: 'text-amber-600', bg: 'bg-amber-50' }
        ].map((kpi, idx) => (
          <div key={idx} className="bg-white/90 backdrop-blur-sm rounded-2xl p-4 border border-slate-100 shadow-sm">
            <p className="text-[10px] font-black uppercase tracking-wider text-slate-400">{kpi.label}</p>
            <p className={`text-2xl font-black mt-1 ${kpi.color}`}>{kpi.val}</p>
          </div>
        ))}
      </div>

      {/* Search & Filter Bar */}
      <div className="bg-white/90 backdrop-blur-sm rounded-2xl p-4 border border-slate-100 shadow-sm flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative flex-1 w-full">
          <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by offer title, subtitle, service key, or badge..."
            className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-600"
          />
        </div>
        <div className="flex items-center gap-2 w-full md:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-rose-600"
          >
            <option value="All">All Schemes</option>
            <option value="Active">Active Only</option>
            <option value="Inactive">Paused / Inactive</option>
          </select>
          <button
            onClick={fetchOffers}
            className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-600 hover:bg-slate-100 transition"
            title="Refresh"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Offers List & Cards */}
      {loading ? (
        <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
          <RefreshCw size={32} className="animate-spin text-rose-600 mx-auto mb-3" />
          <p className="text-xs font-black uppercase tracking-wider text-slate-400">Loading Promotional Offers...</p>
        </div>
      ) : filteredOffers.length === 0 ? (
        <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm space-y-3">
          <div className="w-14 h-14 rounded-2xl bg-rose-50 text-rose-600 flex items-center justify-center mx-auto">
            <Sparkles size={28} />
          </div>
          <h3 className="text-base font-black text-slate-800">No Promotional Schemes Configured</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {searchQuery
              ? 'Try different search keywords.'
              : 'Add your first promotional offer banner or seed the preset schemes.'}
          </p>
          <div className="pt-2">
            <button
              onClick={handleOpenCreate}
              className="px-5 py-2.5 rounded-xl bg-rose-600 text-white text-xs font-black uppercase tracking-wider shadow-md hover:bg-rose-700 transition"
            >
              + Create First Offer
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredOffers.map(offer => (
            <div
              key={offer._id}
              className="bg-white rounded-3xl border border-slate-100 overflow-hidden shadow-sm hover:shadow-xl transition-all duration-300 flex flex-col justify-between group"
            >
              {/* Banner Top Area */}
              <div className="relative h-48 bg-slate-900 overflow-hidden">
                {offer.bannerImageUrl ? (
                  <img
                    src={offer.bannerImageUrl}
                    alt={offer.title}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500 opacity-90"
                  />
                ) : (
                  <div className="w-full h-full bg-gradient-to-br from-slate-900 via-rose-950 to-indigo-900 flex items-center justify-center text-white/20">
                    <Sparkles size={48} />
                  </div>
                )}
                <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/30 to-transparent pointer-events-none" />

                {/* Badge Tag */}
                <div className="absolute top-4 left-4 flex items-center gap-2">
                  <span
                    className="px-3 py-1 rounded-full text-xs font-black text-white uppercase tracking-wider shadow-lg"
                    style={{ backgroundColor: offer.badgeColor || '#DC2626' }}
                  >
                    {offer.badgeTag || 'SPECIAL OFFER'}
                  </span>
                </div>

                {/* Status Switch */}
                <div className="absolute top-4 right-4">
                  <button
                    onClick={() => handleToggleActive(offer)}
                    className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider shadow-md backdrop-blur-md transition ${
                      offer.isActive ? 'bg-emerald-600/90 text-white' : 'bg-slate-900/80 text-amber-300'
                    }`}
                  >
                    {offer.isActive ? '● Live' : '○ Paused'}
                  </button>
                </div>

                {/* Title overlay on banner */}
                <div className="absolute bottom-4 left-4 right-4 text-white">
                  <h3 className="text-lg font-black leading-tight drop-shadow-sm">
                    {offer.title}
                  </h3>
                  <p className="text-xs text-slate-200 mt-1 line-clamp-1 drop-shadow-sm">
                    {offer.subtitle}
                  </p>
                </div>
              </div>

              {/* Offer Details */}
              <div className="p-5 space-y-4">
                {/* Pricing row */}
                <div className="flex items-center justify-between p-3 rounded-2xl bg-slate-50 border border-slate-100">
                  <div>
                    <p className="text-[10px] font-black uppercase tracking-wider text-slate-400">Offer Price</p>
                    <div className="flex items-baseline gap-2 mt-0.5">
                      <span className="text-xl font-black text-slate-900">
                        ₹{Number(offer.discountedPrice || 0).toLocaleString()}
                      </span>
                      {offer.originalPrice > offer.discountedPrice && (
                        <span className="text-xs font-bold text-slate-400 line-through">
                          ₹{Number(offer.originalPrice || 0).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                  {offer.discountAmount > 0 && (
                    <div className="text-right">
                      <span className="px-2.5 py-1 rounded-lg bg-emerald-100 text-emerald-800 text-xs font-black">
                        SAVE ₹{Number(offer.discountAmount).toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>

                {/* Mapping info */}
                <div className="grid grid-cols-2 gap-2 text-xs text-slate-600">
                  <div>
                    <span className="text-[10px] font-black uppercase text-slate-400 block">Target Service Key</span>
                    <span className="font-bold text-slate-800 font-mono text-[11px] truncate block">
                      {offer.targetServiceKey || 'None (General)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-black uppercase text-slate-400 block">Eligibility</span>
                    <span className="font-medium text-slate-600 truncate block">
                      {offer.eligibilityText || 'Open to all'}
                    </span>
                  </div>
                </div>

                {/* Footer Controls */}
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-400">
                    Priority: {offer.priority || 0}
                  </span>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setPreviewOffer(offer)}
                      className="p-2 text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition"
                      title="Preview Banner"
                    >
                      <Eye size={16} />
                    </button>
                    <button
                      onClick={() => handleOpenEdit(offer)}
                      className="p-2 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded-xl transition"
                      title="Edit Scheme"
                    >
                      <Edit2 size={16} />
                    </button>
                    <button
                      onClick={() => handleDelete(offer)}
                      className="p-2 text-slate-500 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition"
                      title="Delete Scheme"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* CREATE / EDIT OFFER MODAL */}
      {modalOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-white rounded-3xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="px-6 py-4 bg-slate-900 text-white flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-rose-600 flex items-center justify-center text-white">
                  <Tag size={18} />
                </div>
                <div>
                  <h3 className="font-bold text-base">{editingOfferId ? 'Edit Promotional Scheme' : 'New Promotional Scheme'}</h3>
                  <p className="text-xs text-slate-400">Configure visual banner, pricing discount, and service links</p>
                </div>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-6 space-y-5 custom-scrollbar">
              {/* Title and Subtitle */}
              <div className="space-y-4">
                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Offer Title *
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    placeholder="e.g. New Company Launchpack 2026"
                    className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-rose-600"
                  />
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Subtitle / Promotional Highlights *
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.subtitle}
                    onChange={(e) => setFormData({ ...formData, subtitle: e.target.value })}
                    placeholder="e.g. Pvt Ltd + GST + MSME + 1-Year Free Bookkeeping Trial"
                    className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-medium text-slate-800 focus:outline-none focus:ring-2 focus:ring-rose-600"
                  />
                </div>
              </div>

              {/* Badge Tag & Color */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Badge Tag (e.g. SAVE ₹4,999 / FLAT 40% OFF)
                  </label>
                  <input
                    type="text"
                    value={formData.badgeTag}
                    onChange={(e) => setFormData({ ...formData, badgeTag: e.target.value })}
                    placeholder="SAVE ₹4,999"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-black text-slate-800 uppercase focus:outline-none focus:ring-2 focus:ring-rose-600"
                  />
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Badge Color
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={formData.badgeColor}
                      onChange={(e) => setFormData({ ...formData, badgeColor: e.target.value })}
                      className="w-9 h-9 rounded-xl border border-slate-200 p-0.5 cursor-pointer"
                    />
                    <div className="flex items-center gap-1.5 flex-1 overflow-x-auto">
                      {PRESET_BADGE_COLORS.map(p => (
                        <button
                          key={p.color}
                          type="button"
                          onClick={() => setFormData({ ...formData, badgeColor: p.color })}
                          className="w-6 h-6 rounded-full border-2 border-white shadow-sm shrink-0"
                          style={{ backgroundColor: p.color }}
                          title={p.name}
                        />
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Banner Image URL */}
              <div>
                <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                  High-Res Banner Image URL (Cloud, CDN or direct asset link)
                </label>
                <div className="flex gap-2">
                  <input
                    type="url"
                    value={formData.bannerImageUrl}
                    onChange={(e) => setFormData({ ...formData, bannerImageUrl: e.target.value })}
                    placeholder="https://images.unsplash.com/photo-..."
                    className="flex-1 px-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-rose-600"
                  />
                  {formData.bannerImageUrl && (
                    <div className="w-10 h-10 rounded-xl overflow-hidden border border-slate-200 shrink-0">
                      <img src={formData.bannerImageUrl} alt="Preview" className="w-full h-full object-cover" />
                    </div>
                  )}
                </div>
              </div>

              {/* Pricing Configurator */}
              <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-3">
                <p className="text-xs font-black uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                  <Percent size={14} className="text-rose-600" /> Pricing & Discount Configurator
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-[10px] font-black uppercase text-slate-500 block mb-1">
                      Original Price (₹)
                    </label>
                    <input
                      type="number"
                      value={formData.originalPrice}
                      onChange={(e) => handlePriceCalculations('originalPrice', e.target.value)}
                      placeholder="12999"
                      className="w-full px-3 py-2 bg-white border border-slate-200 rounded-xl text-xs font-bold text-slate-800"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-black uppercase text-slate-500 block mb-1">
                      Discounted Price (₹)
                    </label>
                    <input
                      type="number"
                      value={formData.discountedPrice}
                      onChange={(e) => handlePriceCalculations('discountedPrice', e.target.value)}
                      placeholder="7999"
                      className="w-full px-3 py-2 bg-white border border-slate-200 rounded-xl text-xs font-bold text-slate-800"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-black uppercase text-slate-500 block mb-1">
                      Savings Amount (₹)
                    </label>
                    <input
                      type="number"
                      value={formData.discountAmount}
                      onChange={(e) => setFormData({ ...formData, discountAmount: Number(e.target.value) })}
                      placeholder="4999"
                      className="w-full px-3 py-2 bg-white border border-slate-200 rounded-xl text-xs font-bold text-emerald-600"
                    />
                  </div>
                </div>
              </div>

              {/* Target Service Key & CTA */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Target Service Key (Slug)
                  </label>
                  <input
                    type="text"
                    value={formData.targetServiceKey}
                    onChange={(e) => setFormData({ ...formData, targetServiceKey: e.target.value })}
                    placeholder="e.g. pvt-ltd-incorporation"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-rose-600"
                  />
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Call To Action Button Text
                  </label>
                  <input
                    type="text"
                    value={formData.ctaText}
                    onChange={(e) => setFormData({ ...formData, ctaText: e.target.value })}
                    placeholder="Register Today →"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-rose-600"
                  />
                </div>
              </div>

              {/* Eligibility & Priority */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="sm:col-span-2">
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Eligibility / Terms Hint
                  </label>
                  <input
                    type="text"
                    value={formData.eligibilityText}
                    onChange={(e) => setFormData({ ...formData, eligibilityText: e.target.value })}
                    placeholder="Valid for first 50 registrations"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-700"
                  />
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Priority (0-100)
                  </label>
                  <input
                    type="number"
                    value={formData.priority}
                    onChange={(e) => setFormData({ ...formData, priority: Number(e.target.value) })}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700"
                  />
                </div>
              </div>

              {/* Active Toggle & Valid Until */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-2 border-t border-slate-100">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.isActive}
                    onChange={(e) => setFormData({ ...formData, isActive: e.target.checked })}
                    className="w-4 h-4 text-rose-600 rounded focus:ring-rose-500 border-slate-300"
                  />
                  <span className="text-xs font-bold text-slate-800">Activate Scheme (Show on App & Web Carousels)</span>
                </label>

                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Valid Until:</span>
                  <input
                    type="date"
                    value={formData.validUntil}
                    onChange={(e) => setFormData({ ...formData, validUntil: e.target.value })}
                    className="px-2.5 py-1 bg-slate-50 border border-slate-200 rounded-lg text-xs font-bold text-slate-700"
                  />
                </div>
              </div>

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-5 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-black uppercase tracking-wider transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-6 py-2.5 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-rose-600/30 transition flex items-center gap-2"
                >
                  {submitting ? <RefreshCw size={14} className="animate-spin" /> : null}
                  {editingOfferId ? 'Save Changes' : 'Publish Scheme'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* PREVIEW BANNER MODAL */}
      {previewOffer && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/70 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-white rounded-3xl max-w-xl w-full flex flex-col shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="px-6 py-4 bg-slate-900 text-white flex items-center justify-between">
              <span className="text-xs font-black uppercase tracking-wider text-rose-300">Live Banner Preview</span>
              <button
                onClick={() => setPreviewOffer(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition"
              >
                <X size={18} />
              </button>
            </div>

            <div className="p-6 space-y-4">
              {/* Carousel Banner Look */}
              <div className="relative rounded-2xl h-56 bg-slate-900 overflow-hidden shadow-xl">
                {previewOffer.bannerImageUrl && (
                  <img src={previewOffer.bannerImageUrl} alt={previewOffer.title} className="w-full h-full object-cover" />
                )}
                <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/40 to-transparent" />
                <div className="absolute top-4 left-4">
                  <span
                    className="px-3 py-1 rounded-full text-xs font-black text-white uppercase tracking-wider shadow-lg"
                    style={{ backgroundColor: previewOffer.badgeColor || '#DC2626' }}
                  >
                    {previewOffer.badgeTag || 'SPECIAL OFFER'}
                  </span>
                </div>
                <div className="absolute bottom-4 left-4 right-4 text-white space-y-1">
                  <h3 className="text-xl font-black">{previewOffer.title}</h3>
                  <p className="text-xs text-slate-200">{previewOffer.subtitle}</p>
                  <div className="flex items-center justify-between pt-2">
                    <div className="flex items-baseline gap-2">
                      <span className="text-xl font-black text-white">₹{Number(previewOffer.discountedPrice || 0).toLocaleString()}</span>
                      {previewOffer.originalPrice > previewOffer.discountedPrice && (
                        <span className="text-xs text-slate-300 line-through">₹{Number(previewOffer.originalPrice).toLocaleString()}</span>
                      )}
                    </div>
                    <span className="px-3 py-1 bg-white text-slate-900 rounded-xl text-xs font-black shadow-md">
                      {previewOffer.ctaText || 'Register →'}
                    </span>
                  </div>
                </div>
              </div>

              <p className="text-[11px] text-slate-400 text-center italic">
                This banner renders dynamically in the header carousel of Web, Android, and iOS.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
