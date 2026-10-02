import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import {
  BookOpen,
  Plus,
  Search,
  Edit2,
  Trash2,
  Eye,
  CheckCircle2,
  XCircle,
  Clock,
  Tag,
  Sparkles,
  ExternalLink,
  Layers,
  ArrowRight,
  RefreshCw,
  X,
  AlertCircle
} from 'lucide-react';

const CATEGORIES = [
  'Corporate & Legal',
  'GST & Direct Taxes',
  'Startups & Funding',
  'IPR & Legal',
  'Accounting & Payroll',
  'Compliance Alert'
];

const CATEGORY_COLORS = {
  'Corporate & Legal': '#3B82F6',
  'GST & Direct Taxes': '#10B981',
  'Startups & Funding': '#8B5CF6',
  'IPR & Legal': '#EC4899',
  'Accounting & Payroll': '#F59E0B',
  'Compliance Alert': '#EF4444'
};

const INITIAL_FORM = {
  title: '',
  slug: '',
  summary: '',
  category: 'Corporate & Legal',
  categoryColor: '#3B82F6',
  readTime: '4 min read',
  coverImageUrl: '',
  keyTakeaways: [''],
  fullArticle: '',
  isPublished: true,
  priority: 0,
  author: 'VR HERE Editorial Board'
};

const DEFAULT_SAMPLE_BLOGS = [
  {
    title: 'New MCA Compliance Filings for Private Limited Companies in 2026',
    slug: 'new-mca-compliance-filings-pvt-ltd-2026',
    summary: 'Essential updates on annual MCA return mandates, board meeting disclosures, and MSME payment compliance for Indian enterprises.',
    category: 'Corporate & Legal',
    categoryColor: '#3B82F6',
    readTime: '5 min read',
    coverImageUrl: 'https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=800&auto=format&fit=crop&q=80',
    keyTakeaways: [
      'Annual DIR-3 KYC verification deadline strict guidelines.',
      'Mandatory half-yearly reporting of pending MSME dues via MSME-1.',
      'Revised threshold for mandatory statutory audits.'
    ],
    fullArticle: `The Ministry of Corporate Affairs (MCA) has introduced reinforced compliance benchmarks for FY 2026-27 to ensure greater corporate transparency and timely reporting.\n\n### 1. Mandatory DIR-3 KYC for All Active Directors\nEvery person holding a Director Identification Number (DIN) must complete annual biometric/web-based KYC before September 30.\n\n### 2. Form MSME-1 Semi-Annual Filings\nSpecified companies with vendor invoices outstanding beyond 45 days must file MSME-1 disclosures with interest computation.\n\n### 3. Statutory Audit & Financial Disclosures\nCompanies must ensure statutory balance sheet disclosures strictly conform to Schedule III requirements.`,
    isPublished: true,
    priority: 10,
    author: 'VR HERE Corporate Legal Desk'
  },
  {
    title: 'GST E-Invoicing & ITC Reconciliation Best Practices for SMBs',
    slug: 'gst-e-invoicing-itc-reconciliation-best-practices',
    summary: 'How to automate GSTR-2B vs Books reconciliation, prevent 18% reversal penalties, and generate IRN e-invoices effortlessly.',
    category: 'GST & Direct Taxes',
    categoryColor: '#10B981',
    readTime: '4 min read',
    coverImageUrl: 'https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=800&auto=format&fit=crop&q=80',
    keyTakeaways: [
      'GSTR-2B matched credit is strictly non-negotiable for ITC claims.',
      'E-invoicing IRN generation must be done within stipulated timeline.',
      'Vendor follow-up automation reduces blocked working capital.'
    ],
    fullArticle: `Input Tax Credit (ITC) management under GST is now strictly governed by dynamic GSTR-2B matching.\n\n### Real-time Ledger Verification\nTaxpayers can no longer claim provisional ITC beyond what vendors reflect in their GSTR-1 filings.\n\n### VR HERE Bookkeeping & AaaS Advantage\nWith our direct Tally and ERP reconciliation engine, your team gets automated mismatched vendor reports every 11th of the month.`,
    isPublished: true,
    priority: 8,
    author: 'VR HERE Tax Advisory Cell'
  }
];

export default function AdminBlogsView({ token }) {
  const [blogs, setBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [modalOpen, setModalOpen] = useState(false);
  const [previewBlog, setPreviewBlog] = useState(null);
  const [editingBlogId, setEditingBlogId] = useState(null);
  const [formData, setFormData] = useState(INITIAL_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [actionMessage, setActionMessage] = useState({ text: '', type: '' });

  const authHeader = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const showNotification = (text, type = 'success') => {
    setActionMessage({ text, type });
    setTimeout(() => setActionMessage({ text: '', type: '' }), 4000);
  };

  const fetchBlogs = async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/blogs/admin/all', authHeader);
      setBlogs(res.data || []);
    } catch (err) {
      console.error('Failed to load blogs:', err);
      showNotification(err.response?.data?.message || 'Failed to fetch blogs', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlogs();
  }, [authHeader]);

  const handleOpenCreate = () => {
    setEditingBlogId(null);
    setFormData(INITIAL_FORM);
    setModalOpen(true);
  };

  const handleOpenEdit = (blog) => {
    setEditingBlogId(blog._id);
    setFormData({
      title: blog.title || '',
      slug: blog.slug || '',
      summary: blog.summary || '',
      category: blog.category || 'Corporate & Legal',
      categoryColor: blog.categoryColor || CATEGORY_COLORS[blog.category] || '#3B82F6',
      readTime: blog.readTime || '4 min read',
      coverImageUrl: blog.coverImageUrl || '',
      keyTakeaways: blog.keyTakeaways && blog.keyTakeaways.length > 0 ? blog.keyTakeaways : [''],
      fullArticle: blog.fullArticle || '',
      isPublished: blog.isPublished !== undefined ? blog.isPublished : true,
      priority: blog.priority || 0,
      author: blog.author || 'VR HERE Editorial Board'
    });
    setModalOpen(true);
  };

  const handleTitleChange = (val) => {
    setFormData(prev => ({
      ...prev,
      title: val,
      slug: !editingBlogId ? val.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') : prev.slug
    }));
  };

  const handleAddTakeaway = () => {
    setFormData(prev => ({
      ...prev,
      keyTakeaways: [...prev.keyTakeaways, '']
    }));
  };

  const handleRemoveTakeaway = (idx) => {
    setFormData(prev => ({
      ...prev,
      keyTakeaways: prev.keyTakeaways.filter((_, i) => i !== idx)
    }));
  };

  const handleTakeawayChange = (idx, text) => {
    setFormData(prev => {
      const updated = [...prev.keyTakeaways];
      updated[idx] = text;
      return { ...prev, keyTakeaways: updated };
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.title.trim() || !formData.summary.trim() || !formData.fullArticle.trim()) {
      showNotification('Title, summary, and article content are required.', 'error');
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        ...formData,
        keyTakeaways: formData.keyTakeaways.filter(t => t.trim().length > 0)
      };

      if (editingBlogId) {
        await axios.put(`/api/blogs/${editingBlogId}`, payload, authHeader);
        showNotification('Article updated successfully!');
      } else {
        await axios.post('/api/blogs', payload, authHeader);
        showNotification('Article published successfully!');
      }
      setModalOpen(false);
      fetchBlogs();
    } catch (err) {
      console.error('Submit failed:', err);
      showNotification(err.response?.data?.message || 'Operation failed', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (blog) => {
    if (!window.confirm(`Are you sure you want to delete "${blog.title}"?`)) return;
    try {
      await axios.delete(`/api/blogs/${blog._id}`, authHeader);
      showNotification('Article deleted successfully');
      fetchBlogs();
    } catch (err) {
      console.error('Delete failed:', err);
      showNotification(err.response?.data?.message || 'Delete failed', 'error');
    }
  };

  const handleTogglePublished = async (blog) => {
    try {
      await axios.put(`/api/blogs/${blog._id}`, { isPublished: !blog.isPublished }, authHeader);
      showNotification(`Article ${!blog.isPublished ? 'published' : 'moved to drafts'}`);
      fetchBlogs();
    } catch (err) {
      console.error('Toggle status failed:', err);
      showNotification('Failed to update status', 'error');
    }
  };

  const handleSeedDefaults = async () => {
    if (!window.confirm('Seed default sample regulatory insights & articles?')) return;
    try {
      setLoading(true);
      for (const b of DEFAULT_SAMPLE_BLOGS) {
        await axios.post('/api/blogs', b, authHeader);
      }
      showNotification('Default articles seeded successfully!');
      fetchBlogs();
    } catch (err) {
      console.error('Seed failed:', err);
      showNotification('Failed to seed defaults', 'error');
    } finally {
      setLoading(false);
    }
  };

  const filteredBlogs = useMemo(() => {
    return blogs.filter(b => {
      const matchSearch = b.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          b.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          b.category.toLowerCase().includes(searchQuery.toLowerCase());
      const matchCategory = selectedCategory === 'All' || b.category === selectedCategory;
      const matchStatus = statusFilter === 'All' ||
                          (statusFilter === 'Published' && b.isPublished) ||
                          (statusFilter === 'Draft' && !b.isPublished);
      return matchSearch && matchCategory && matchStatus;
    });
  }, [blogs, searchQuery, selectedCategory, statusFilter]);

  return (
    <div className="space-y-6">
      {/* Toast alert */}
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
      <div className="rounded-3xl bg-gradient-to-r from-slate-900 via-indigo-950 to-blue-950 p-6 sm:p-8 text-white relative overflow-hidden shadow-xl">
        <div className="absolute right-0 top-0 p-8 opacity-10 pointer-events-none">
          <BookOpen size={160} />
        </div>
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 text-cyan-300 text-[10px] font-black uppercase tracking-widest backdrop-blur-md mb-3">
              <Sparkles size={12} /> Cross-Platform CMS Studio
            </div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight">Blogs & Regulatory Insights</h1>
            <p className="text-slate-300 text-sm mt-1 max-w-xl">
              Create, edit, and publish verified legal, GST, and MCA compliance articles. Synchronized live across Web, Android, and iOS.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {blogs.length === 0 && (
              <button
                onClick={handleSeedDefaults}
                className="px-4 py-3 rounded-2xl bg-white/10 hover:bg-white/20 text-white text-xs font-black uppercase tracking-wider transition backdrop-blur-md flex items-center gap-2"
              >
                <Sparkles size={16} className="text-cyan-300" /> Seed Sample Insights
              </button>
            )}
            <button
              onClick={handleOpenCreate}
              className="px-5 py-3 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-black uppercase tracking-wider transition shadow-lg shadow-indigo-600/30 flex items-center gap-2 active:scale-95"
            >
              <Plus size={18} /> New Article
            </button>
          </div>
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Articles', val: blogs.length, color: 'text-indigo-600', bg: 'bg-indigo-50' },
          { label: 'Published & Live', val: blogs.filter(b => b.isPublished).length, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Drafts', val: blogs.filter(b => !b.isPublished).length, color: 'text-amber-600', bg: 'bg-amber-50' },
          { label: 'Active Categories', val: new Set(blogs.map(b => b.category)).size, color: 'text-blue-600', bg: 'bg-blue-50' }
        ].map((kpi, idx) => (
          <div key={idx} className="bg-white/90 backdrop-blur-sm rounded-2xl p-4 border border-slate-100 shadow-sm">
            <p className="text-[10px] font-black uppercase tracking-wider text-slate-400">{kpi.label}</p>
            <p className={`text-2xl font-black mt-1 ${kpi.color}`}>{kpi.val}</p>
          </div>
        ))}
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white/90 backdrop-blur-sm rounded-2xl p-4 border border-slate-100 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by title, keywords, or takeaways..."
              className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-600"
            />
          </div>
          <div className="flex items-center gap-2 w-full md:w-auto">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-600"
            >
              <option value="All">All Statuses</option>
              <option value="Published">Published Only</option>
              <option value="Draft">Drafts Only</option>
            </select>
            <button
              onClick={fetchBlogs}
              className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-600 hover:bg-slate-100 transition"
              title="Refresh"
            >
              <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Category Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 custom-scrollbar">
          <button
            onClick={() => setSelectedCategory('All')}
            className={`px-3 py-1.5 rounded-xl text-xs font-black transition whitespace-nowrap ${
              selectedCategory === 'All' ? 'bg-slate-900 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            All Categories ({blogs.length})
          </button>
          {CATEGORIES.map(cat => {
            const count = blogs.filter(b => b.category === cat).length;
            const active = selectedCategory === cat;
            return (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
                  active ? 'bg-indigo-600 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: CATEGORY_COLORS[cat] || '#3B82F6' }} />
                <span>{cat}</span>
                <span className="opacity-70 text-[10px]">({count})</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Blogs Grid */}
      {loading ? (
        <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
          <RefreshCw size={32} className="animate-spin text-indigo-600 mx-auto mb-3" />
          <p className="text-xs font-black uppercase tracking-wider text-slate-400">Loading Regulatory Insights...</p>
        </div>
      ) : filteredBlogs.length === 0 ? (
        <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm space-y-3">
          <div className="w-14 h-14 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center mx-auto">
            <BookOpen size={28} />
          </div>
          <h3 className="text-base font-black text-slate-800">No Articles Found</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {searchQuery || selectedCategory !== 'All'
              ? 'Try changing your search keywords or filter category.'
              : 'Create your first regulatory insight or seed the sample insights.'}
          </p>
          <div className="pt-2">
            <button
              onClick={handleOpenCreate}
              className="px-5 py-2.5 rounded-xl bg-indigo-600 text-white text-xs font-black uppercase tracking-wider shadow-md hover:bg-indigo-700 transition"
            >
              + Create First Article
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
          {filteredBlogs.map(blog => (
            <div
              key={blog._id}
              className="bg-white rounded-3xl border border-slate-100 overflow-hidden shadow-sm hover:shadow-xl transition-all duration-300 flex flex-col group"
            >
              {/* Cover Image */}
              <div className="h-44 w-full bg-slate-100 relative overflow-hidden">
                {blog.coverImageUrl ? (
                  <img
                    src={blog.coverImageUrl}
                    alt={blog.title}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                  />
                ) : (
                  <div className="w-full h-full bg-gradient-to-br from-indigo-900 to-slate-900 flex items-center justify-center text-white/20">
                    <BookOpen size={48} />
                  </div>
                )}
                <div className="absolute top-3 left-3 flex items-center gap-2">
                  <span
                    className="px-2.5 py-1 rounded-full text-[10px] font-black text-white uppercase tracking-wider shadow-md"
                    style={{ backgroundColor: blog.categoryColor || CATEGORY_COLORS[blog.category] || '#3B82F6' }}
                  >
                    {blog.category}
                  </span>
                </div>
                <div className="absolute top-3 right-3">
                  <button
                    onClick={() => handleTogglePublished(blog)}
                    className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider shadow-md backdrop-blur-md transition ${
                      blog.isPublished ? 'bg-emerald-600/90 text-white' : 'bg-slate-900/80 text-amber-300'
                    }`}
                  >
                    {blog.isPublished ? '● Published' : '○ Draft'}
                  </button>
                </div>
                <div className="absolute bottom-3 right-3 bg-black/60 backdrop-blur-md px-2 py-0.5 rounded-md text-[10px] font-bold text-white flex items-center gap-1">
                  <Clock size={10} /> {blog.readTime || '4 min read'}
                </div>
              </div>

              {/* Body */}
              <div className="p-5 flex-1 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <h3 className="font-black text-slate-900 text-base leading-snug group-hover:text-indigo-600 transition-colors line-clamp-2">
                    {blog.title}
                  </h3>
                  <p className="text-xs text-slate-500 line-clamp-3 leading-relaxed">
                    {blog.summary}
                  </p>

                  {blog.keyTakeaways && blog.keyTakeaways.length > 0 && (
                    <div className="pt-2 border-t border-slate-100">
                      <p className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1.5">
                        Key Takeaways ({blog.keyTakeaways.length})
                      </p>
                      <ul className="space-y-1">
                        {blog.keyTakeaways.slice(0, 2).map((takeaway, tIdx) => (
                          <li key={tIdx} className="text-xs text-slate-600 font-medium flex items-start gap-1.5">
                            <span className="text-emerald-500 font-black shrink-0">✓</span>
                            <span className="line-clamp-1">{takeaway}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Footer Controls */}
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-400">
                    Priority: {blog.priority || 0}
                  </span>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setPreviewBlog(blog)}
                      className="p-2 text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition"
                      title="Preview Article"
                    >
                      <Eye size={16} />
                    </button>
                    <button
                      onClick={() => handleOpenEdit(blog)}
                      className="p-2 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded-xl transition"
                      title="Edit Article"
                    >
                      <Edit2 size={16} />
                    </button>
                    <button
                      onClick={() => handleDelete(blog)}
                      className="p-2 text-slate-500 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition"
                      title="Delete Article"
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

      {/* CREATE / EDIT MODAL */}
      {modalOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-white rounded-3xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="px-6 py-4 bg-slate-900 text-white flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center text-white">
                  <BookOpen size={18} />
                </div>
                <div>
                  <h3 className="font-bold text-base">{editingBlogId ? 'Edit Article' : 'New Article'}</h3>
                  <p className="text-xs text-slate-400">Publish verified regulatory insights & blogs</p>
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
              {/* Title & Slug */}
              <div className="space-y-4">
                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Article Title *
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.title}
                    onChange={(e) => handleTitleChange(e.target.value)}
                    placeholder="e.g. New MCA Compliance Filings for Private Limited Companies"
                    className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                  />
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    URL Slug (Unique identifier) *
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.slug}
                    onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
                    placeholder="e.g. new-mca-compliance-filings-pvt-ltd-2026"
                    className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                  />
                </div>
              </div>

              {/* Category, Color, Read Time & Priority */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Category *
                  </label>
                  <select
                    value={formData.category}
                    onChange={(e) => {
                      const cat = e.target.value;
                      setFormData({
                        ...formData,
                        category: cat,
                        categoryColor: CATEGORY_COLORS[cat] || formData.categoryColor
                      });
                    }}
                    className="w-full px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                  >
                    {CATEGORIES.map(c => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Estimated Read Time
                  </label>
                  <input
                    type="text"
                    value={formData.readTime}
                    onChange={(e) => setFormData({ ...formData, readTime: e.target.value })}
                    placeholder="e.g. 4 min read"
                    className="w-full px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                  />
                </div>

                <div>
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                    Display Priority (0-100)
                  </label>
                  <input
                    type="number"
                    value={formData.priority}
                    onChange={(e) => setFormData({ ...formData, priority: Number(e.target.value) })}
                    className="w-full px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                  />
                </div>
              </div>

              {/* Cover Image URL */}
              <div>
                <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                  Cover Image URL (Direct image or Unsplash link)
                </label>
                <div className="flex gap-2">
                  <input
                    type="url"
                    value={formData.coverImageUrl}
                    onChange={(e) => setFormData({ ...formData, coverImageUrl: e.target.value })}
                    placeholder="https://images.unsplash.com/photo-..."
                    className="flex-1 px-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                  />
                  {formData.coverImageUrl && (
                    <div className="w-10 h-10 rounded-xl overflow-hidden border border-slate-200 shrink-0">
                      <img src={formData.coverImageUrl} alt="Preview" className="w-full h-full object-cover" />
                    </div>
                  )}
                </div>
              </div>

              {/* Summary / Lead Paragraph */}
              <div>
                <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                  Summary / Lead Paragraph *
                </label>
                <textarea
                  required
                  rows={2}
                  value={formData.summary}
                  onChange={(e) => setFormData({ ...formData, summary: e.target.value })}
                  placeholder="Concise overview summarizing the regulatory change or key insight..."
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-medium text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                />
              </div>

              {/* Dynamic Key Takeaways */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs font-black uppercase tracking-wider text-slate-600">
                    Key Takeaways (Bullet Points)
                  </label>
                  <button
                    type="button"
                    onClick={handleAddTakeaway}
                    className="text-xs font-black text-indigo-600 hover:text-indigo-700 flex items-center gap-1"
                  >
                    <Plus size={14} /> Add Bullet
                  </button>
                </div>
                <div className="space-y-2">
                  {formData.keyTakeaways.map((takeaway, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <span className="w-5 text-center text-xs font-bold text-slate-400">{idx + 1}.</span>
                      <input
                        type="text"
                        value={takeaway}
                        onChange={(e) => handleTakeawayChange(idx, e.target.value)}
                        placeholder={`Bullet point ${idx + 1}...`}
                        className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-600"
                      />
                      {formData.keyTakeaways.length > 1 && (
                        <button
                          type="button"
                          onClick={() => handleRemoveTakeaway(idx)}
                          className="p-2 text-slate-400 hover:text-rose-500 rounded-lg hover:bg-rose-50 transition"
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Full Article Content */}
              <div>
                <label className="text-xs font-black uppercase tracking-wider text-slate-600 block mb-1">
                  Full Article Content (Markdown or formatted text) *
                </label>
                <textarea
                  required
                  rows={8}
                  value={formData.fullArticle}
                  onChange={(e) => setFormData({ ...formData, fullArticle: e.target.value })}
                  placeholder="### Heading 1&#10;Write comprehensive step-by-step guidance, legal provisions, and expert commentary here..."
                  className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-600 leading-relaxed"
                />
              </div>

              {/* Published Toggle & Author */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-2 border-t border-slate-100">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.isPublished}
                    onChange={(e) => setFormData({ ...formData, isPublished: e.target.checked })}
                    className="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500 border-slate-300"
                  />
                  <span className="text-xs font-bold text-slate-800">Publish Immediately (Visible to All Users)</span>
                </label>

                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Author:</span>
                  <input
                    type="text"
                    value={formData.author}
                    onChange={(e) => setFormData({ ...formData, author: e.target.value })}
                    className="px-2.5 py-1 bg-slate-50 border border-slate-200 rounded-lg text-xs font-bold text-slate-700"
                  />
                </div>
              </div>

              {/* Action Buttons */}
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
                  className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-indigo-600/30 transition flex items-center gap-2"
                >
                  {submitting ? <RefreshCw size={14} className="animate-spin" /> : null}
                  {editingBlogId ? 'Save Changes' : 'Publish Article'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* PREVIEW DRAWER / MODAL */}
      {previewBlog && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/70 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-white rounded-3xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-200">
            {/* Header */}
            <div className="px-6 py-4 bg-slate-900 text-white flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase text-white"
                  style={{ backgroundColor: previewBlog.categoryColor || '#3B82F6' }}
                >
                  {previewBlog.category}
                </span>
                <span className="text-xs text-slate-400">• {previewBlog.readTime || '4 min read'}</span>
              </div>
              <button
                onClick={() => setPreviewBlog(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition"
              >
                <X size={18} />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">
              {previewBlog.coverImageUrl && (
                <div className="h-56 w-full rounded-2xl overflow-hidden border border-slate-100">
                  <img src={previewBlog.coverImageUrl} alt={previewBlog.title} className="w-full h-full object-cover" />
                </div>
              )}

              <div>
                <h1 className="text-2xl font-black text-slate-900 leading-tight">
                  {previewBlog.title}
                </h1>
                <p className="text-xs text-slate-400 mt-2">
                  By <span className="font-bold text-slate-600">{previewBlog.author || 'VR HERE Editorial Board'}</span> • Published on {new Date(previewBlog.publishedAt || Date.now()).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-indigo-50/70 border border-indigo-100 text-xs font-semibold text-slate-800 leading-relaxed">
                {previewBlog.summary}
              </div>

              {previewBlog.keyTakeaways && previewBlog.keyTakeaways.length > 0 && (
                <div className="p-5 rounded-2xl bg-slate-50 border border-slate-100 space-y-2">
                  <p className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-2">
                    <Sparkles size={14} className="text-indigo-600" /> Key Takeaways
                  </p>
                  <ul className="space-y-1.5">
                    {previewBlog.keyTakeaways.map((t, idx) => (
                      <li key={idx} className="text-xs text-slate-700 flex items-start gap-2">
                        <span className="text-emerald-600 font-black">✓</span>
                        <span>{t}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="prose prose-sm max-w-none text-slate-700 text-xs leading-relaxed whitespace-pre-wrap">
                {previewBlog.fullArticle}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
