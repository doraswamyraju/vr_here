import React, { useMemo, useState, useEffect } from 'react';
import { 
  Download, 
  FileText, 
  FolderOpen, 
  Upload, 
  ShieldCheck, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  FileCheck, 
  ExternalLink, 
  Plus, 
  RefreshCw,
  Search,
  Eye,
  Trash2,
  Building2,
  UserCheck,
  Filter,
  Check,
  X,
  Sparkles,
  Layers,
  FileSpreadsheet,
  FileCode,
  FileArchive,
  Maximize2
} from 'lucide-react';
import axios from 'axios';
import RequirementsWorkspace from './RequirementsWorkspace';
import ITRAssessmentCustomerView from './ITRAssessmentCustomerView';

const MASTER_KYC_TYPES = [
  { id: 'PAN Card', label: 'PAN Card (Company/Director)', icon: Building2, desc: 'Permanent Account Number proof' },
  { id: 'Aadhaar Card', label: 'Aadhaar Card (Director/Proprietor)', icon: UserCheck, desc: 'Identity & Address verification' },
  { id: 'GST Certificate', label: 'GST Registration Certificate', icon: FileCheck, desc: 'Form GST REG-06 or application' },
  { id: 'Cancelled Cheque', label: 'Cancelled Cheque / Bank Proof', icon: FileText, desc: 'Bank account validation with IFSC & Account No.' },
  { id: 'Business Address Proof', label: 'Business Address Proof (Electricity/Rent)', icon: Building2, desc: 'Utility bill under 2 months or registered rent agreement' },
  { id: 'Incorporation Certificate', label: 'Certificate of Incorporation / Registration', icon: ShieldCheck, desc: 'MCA Certificate, Partnership Deed, or Trade License' },
  { id: 'MSME / Udyam Certificate', label: 'MSME / Udyam Registration', icon: Sparkles, desc: 'Government MSME recognition certificate' },
  { id: 'MOA & AOA', label: 'MOA & AOA / Partnership Deed', icon: Layers, desc: 'Charter documents and bylaws' },
];

const DOC_TYPE_KEYWORDS = {
  'PAN Card': ['pan', 'pancard'],
  'Aadhaar Card': ['aadhaar', 'aadhar', 'adhar', 'uidai'],
  'GST Certificate': ['gst', 'gstin', 'reg06', 'gst_cert'],
  'Cancelled Cheque': ['cheque', 'check', 'bank', 'passbook', 'statement'],
  'Business Address Proof': ['address', 'proof', 'utility', 'bill', 'rent', 'electricity'],
  'Incorporation Certificate': ['incorporation', 'coi', 'inc', 'registration_certificate'],
  'MSME / Udyam Certificate': ['msme', 'udyam', 'udyog'],
  'MOA & AOA': ['moa', 'aoa', 'deed', 'bylaws']
};

// Helper to determine format & embeddable URL
const parseDocInfo = (url, name = '') => {
  if (!url) return { type: 'unknown', embedUrl: '', rawUrl: '' };
  
  const rawUrl = url;
  const fileName = (name || url).toLowerCase();
  let embedUrl = url;

  // Convert Google Drive view links to preview links
  if (url.includes('drive.google.com')) {
    embedUrl = url.replace(/\/view(\?.*)?$/, '/preview');
    if (!embedUrl.includes('/preview')) {
      embedUrl = `${embedUrl.split('?')[0]}/preview`;
    }
  }

  if (/\.(jpeg|jpg|png|webp|gif|svg)(\?.*)?$/i.test(fileName)) {
    return { type: 'image', embedUrl, rawUrl, ext: 'IMG' };
  }
  if (/\.pdf(\?.*)?$/i.test(fileName)) {
    return { type: 'pdf', embedUrl, rawUrl, ext: 'PDF' };
  }
  if (/\.(xlsx|xls|csv)(\?.*)?$/i.test(fileName)) {
    return { type: 'spreadsheet', embedUrl, rawUrl, ext: 'XLSX' };
  }
  if (/\.(docx|doc|rtf)(\?.*)?$/i.test(fileName)) {
    return { type: 'word', embedUrl, rawUrl, ext: 'DOCX' };
  }
  if (/\.(zip|rar|7z|tar|gz)(\?.*)?$/i.test(fileName)) {
    return { type: 'archive', embedUrl, rawUrl, ext: 'ZIP' };
  }
  if (url.includes('drive.google.com')) {
    return { type: 'gdrive', embedUrl, rawUrl, ext: 'GDRIVE' };
  }

  return { type: 'generic', embedUrl, rawUrl, ext: 'FILE' };
};

const DocumentsView = ({ orders = [], refreshOrders, userInfo }) => {
  const [activeTab, setActiveTab] = useState('provided'); // 'provided', 'master_kyc', 'workspaces', 'explorer'
  const [selectedOrderId, setSelectedOrderId] = useState(orders[0]?._id || '');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterCategory, setFilterCategory] = useState('ALL');
  
  // Profile / Master KYC state
  const [vaultDocuments, setVaultDocuments] = useState([]);
  const [isLoadingVault, setIsLoadingVault] = useState(false);
  const [uploadingDocType, setUploadingDocType] = useState(null);
  
  // Workspace Upload state
  const [stagedFiles, setStagedFiles] = useState([]);
  const [isUploadingOrderDocs, setIsUploadingOrderDocs] = useState(false);
  const [orderUploadStatus, setOrderUploadStatus] = useState('');
  const [isDragging, setIsDragging] = useState(false);

  // Preview Modal state
  const [previewDoc, setPreviewDoc] = useState(null);

  const token = userInfo?.token;

  // Selected Order memo
  const selectedOrder = useMemo(() => {
    return orders.find(o => o._id === selectedOrderId) || orders[0] || null;
  }, [orders, selectedOrderId]);

  // Fetch Master KYC Documents from Google Drive Vault
  const fetchMasterVault = async () => {
    if (!token) return;
    try {
      setIsLoadingVault(true);
      const res = await axios.get('/api/documents', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setVaultDocuments(res.data?.data || []);
    } catch (err) {
      console.error('Failed to load master vault documents:', err);
    } finally {
      setIsLoadingVault(false);
    }
  };

  useEffect(() => {
    fetchMasterVault();
  }, [token]);

  useEffect(() => {
    if (!selectedOrderId && orders.length > 0) {
      setSelectedOrderId(orders[0]._id);
    }
  }, [orders, selectedOrderId]);

  // Master Flattened Files Across Entire Customer Account
  const allFlattenedFiles = useMemo(() => {
    const list = [];

    // 1. Master Vault Documents
    vaultDocuments.forEach(doc => {
      list.push({
        id: `vault_${doc._id}`,
        dbId: doc._id,
        name: doc.fileName || doc.docType,
        docType: doc.docType || 'KYC Document',
        category: 'Master KYC',
        source: 'Google Drive Master Vault',
        url: doc.gdriveWebViewLink || doc.url,
        date: doc.createdAt,
        status: doc.verificationStatus || 'Verified',
        isMasterDoc: true
      });
    });

    // 2. Orders Documents
    orders.forEach(order => {
      const orderName = order.serviceName || `Order #${order._id?.slice(-6).toUpperCase()}`;

      // Final Certificate
      if (order.finalCertificateUrl) {
        list.push({
          id: `cert_${order._id}`,
          name: `${order.serviceName} - Official Final Certificate`,
          docType: 'Official Certificate',
          category: 'Government Deliverable',
          source: orderName,
          orderId: order._id,
          url: order.finalCertificateUrl,
          date: order.updatedAt || order.createdAt,
          status: 'Issued & Approved',
          isCertificate: true
        });
      }

      // Admin Deliverables
      (order.adminDocuments || []).forEach(doc => {
        if (doc && (doc.url || doc.path)) {
          list.push({
            id: `admin_${doc._id || doc.url}`,
            name: doc.name || 'Official Filing Document',
            docType: 'Government Filing / Receipt',
            category: 'Government Deliverable',
            source: orderName,
            orderId: order._id,
            url: doc.url || doc.path,
            date: doc.uploadedAt || order.createdAt,
            status: 'Delivered',
            isCertificate: false
          });
        }
      });

      // Client Uploads
      (order.clientDocuments || []).forEach(doc => {
        if (doc && (doc.url || doc.path)) {
          list.push({
            id: `client_${doc._id || doc.url}`,
            name: doc.name || doc.filename || 'Project Attachment',
            docType: 'Project Upload',
            category: 'Client Upload',
            source: orderName,
            orderId: order._id,
            url: doc.url || doc.path,
            date: doc.uploadedAt || order.createdAt,
            status: 'Uploaded'
          });
        }
      });

      // Customer Requirements Uploads
      (order.customerRequirements || []).forEach(req => {
        const fileUrl = req.uploadedDocumentUrl || req.documentUrl || (req.value && typeof req.value === 'string' && (req.value.startsWith('http') || req.value.startsWith('/uploads')) ? req.value : null);
        if (fileUrl) {
          list.push({
            id: `req_${req._id || fileUrl}`,
            name: req.uploadedDocumentName || req.title || 'Checklist Document',
            docType: req.title || 'Checklist Item',
            category: 'Checklist Upload',
            source: `${orderName} (${req.title})`,
            orderId: order._id,
            url: fileUrl,
            date: req.lastSavedAt || order.createdAt,
            status: req.status || 'Under Review'
          });
        }

        (req.documents || []).forEach((subDoc, sIdx) => {
          if (subDoc && (subDoc.url || subDoc.path)) {
            list.push({
              id: `req_sub_${subDoc._id || sIdx}`,
              name: subDoc.name || `${req.title} Proof`,
              docType: req.title || 'Requirement Document',
              category: 'Checklist Upload',
              source: orderName,
              orderId: order._id,
              url: subDoc.url || subDoc.path,
              date: order.createdAt,
              status: 'Received'
            });
          }
        });
      });
    });

    return list;
  }, [vaultDocuments, orders]);

  // Quick fallback lookup for Master KYC items from existing orders
  const getFallbackForMasterType = (docType) => {
    const keywords = DOC_TYPE_KEYWORDS[docType] || [docType.toLowerCase().split(' ')[0]];
    return allFlattenedFiles.find(file => {
      const nameLower = (file.name || '').toLowerCase();
      const typeLower = (file.docType || '').toLowerCase();
      const sourceLower = (file.source || '').toLowerCase();
      return keywords.some(kw => nameLower.includes(kw) || typeLower.includes(kw) || sourceLower.includes(kw));
    });
  };

  // KPI Calculations
  const stats = useMemo(() => {
    const totalDeliverables = allFlattenedFiles.filter(f => f.category === 'Government Deliverable').length;
    const totalMasterKyc = vaultDocuments.length;
    const totalClientDocs = allFlattenedFiles.filter(f => f.category === 'Client Upload' || f.category === 'Checklist Upload').length;
    
    let pendingReqs = 0;
    orders.forEach(order => {
      (order.customerRequirements || []).forEach(r => {
        if (r.required !== false && !r.isClientCompleted && !r.uploadedDocumentUrl && (!r.documents || r.documents.length === 0) && !r.value && !r.clientValue) {
          pendingReqs++;
        }
      });
    });

    return {
      deliverables: totalDeliverables,
      masterKyc: totalMasterKyc,
      clientDocs: totalClientDocs,
      pendingRequirements: pendingReqs
    };
  }, [allFlattenedFiles, vaultDocuments, orders]);

  // Master Upload Handler (Google Drive Profile Vault)
  const handleUploadMasterKyc = async (docType, file) => {
    if (!file || !token) return;
    try {
      setUploadingDocType(docType);
      const formData = new FormData();
      formData.append('document', file);
      formData.append('docType', docType);

      await axios.post('/api/documents/upload', formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });

      await fetchMasterVault();
      if (refreshOrders) refreshOrders();
    } catch (err) {
      alert(err.response?.data?.message || `Failed to upload ${docType}`);
    } finally {
      setUploadingDocType(null);
    }
  };

  // Delete Master KYC doc
  const handleDeleteMasterKyc = async (docId) => {
    if (!window.confirm('Are you sure you want to remove this verified document from your master vault?')) return;
    try {
      await axios.delete(`/api/documents/${docId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchMasterVault();
    } catch (err) {
      alert('Failed to delete document from vault');
    }
  };

  // Workspace Upload Handler
  const handleUploadOrderFiles = async (e) => {
    e?.preventDefault();
    if (stagedFiles.length === 0 || !selectedOrder) return;

    setIsUploadingOrderDocs(true);
    try {
      for (let i = 0; i < stagedFiles.length; i++) {
        setOrderUploadStatus(`Uploading file ${i + 1} of ${stagedFiles.length}...`);
        const formData = new FormData();
        formData.append('document', stagedFiles[i]);
        formData.append('name', stagedFiles[i].name);

        await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
            Authorization: `Bearer ${token}`
          }
        });
      }
      setStagedFiles([]);
      if (refreshOrders) refreshOrders();
      alert('All documents uploaded to project workspace successfully.');
    } catch (err) {
      alert('Error uploading documents to workspace');
    } finally {
      setIsUploadingOrderDocs(false);
      setOrderUploadStatus('');
    }
  };

  // Filtered files for Explorer Tab
  const explorerFilteredFiles = useMemo(() => {
    return allFlattenedFiles.filter(f => {
      const matchSearch = searchQuery === '' || 
        f.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
        f.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.docType.toLowerCase().includes(searchQuery.toLowerCase());

      const matchCategory = filterCategory === 'ALL' || f.category === filterCategory;

      return matchSearch && matchCategory;
    });
  }, [allFlattenedFiles, searchQuery, filterCategory]);

  return (
    <div className="space-y-6 pb-24 lg:pb-12 animate-in fade-in duration-300">
      
      {/* 1. Hero Banner */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-950 via-slate-900 to-red-950/90 text-white p-6 sm:p-8 shadow-2xl border border-slate-800">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-72 h-72 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-1/3 -mb-12 w-64 h-64 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-3 py-1 bg-red-500/20 text-red-300 border border-red-500/30 text-[11px] font-black rounded-full uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck size={13} className="text-red-400" />
                Cloud-Synced Vault
              </span>
              <span className="px-3 py-1 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[11px] font-bold rounded-full uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 size={13} />
                AES-256 Encrypted
              </span>
              <span className="px-3 py-1 bg-slate-800/80 text-slate-300 text-[11px] font-medium rounded-full">
                ISO 27001:2022 Certified
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white flex items-center gap-3">
              Document Vault & Compliance Repository
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 font-normal leading-relaxed">
              Your centralized, high-security repository for verified government deliverables, corporate incorporation certificates, tax filings, and master KYC proofs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 self-start lg:self-center shrink-0">
            <button
              onClick={() => {
                fetchMasterVault();
                if (refreshOrders) refreshOrders();
              }}
              disabled={isLoadingVault}
              className="px-4 py-2.5 bg-white/10 hover:bg-white/20 active:scale-95 text-white text-xs font-bold rounded-xl border border-white/10 transition-all flex items-center gap-2 shadow-sm backdrop-blur-md"
              title="Synchronize vault with Google Drive"
            >
              <RefreshCw size={14} className={isLoadingVault ? 'animate-spin' : ''} />
              <span>{isLoadingVault ? 'Syncing...' : 'Sync Vault'}</span>
            </button>

            <button
              onClick={() => setActiveTab('master_kyc')}
              className="px-5 py-2.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 active:scale-95 text-white text-xs font-black rounded-xl transition-all shadow-lg shadow-red-600/30 flex items-center gap-2"
            >
              <Plus size={15} />
              <span>Upload Master KYC</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Interactive KPI Stats Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Stat 1: Government Deliverables */}
        <div 
          onClick={() => setActiveTab('provided')}
          className={`cursor-pointer rounded-2xl p-5 border transition-all transform hover:-translate-y-0.5 ${
            activeTab === 'provided' 
              ? 'bg-emerald-50/50 border-emerald-300 shadow-md ring-2 ring-emerald-500/20' 
              : 'bg-white border-slate-200/90 shadow-2xs hover:border-emerald-200'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Govt Deliverables</span>
            <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center font-bold">
              <FileCheck size={16} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <h3 className="text-2xl font-black text-slate-900">{stats.deliverables}</h3>
            <span className="text-[11px] font-bold text-emerald-600">Issued</span>
          </div>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Approved certificates & filings</p>
        </div>

        {/* Stat 2: Master Profile KYC */}
        <div 
          onClick={() => setActiveTab('master_kyc')}
          className={`cursor-pointer rounded-2xl p-5 border transition-all transform hover:-translate-y-0.5 ${
            activeTab === 'master_kyc' 
              ? 'bg-blue-50/50 border-blue-300 shadow-md ring-2 ring-blue-500/20' 
              : 'bg-white border-slate-200/90 shadow-2xs hover:border-blue-200'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Master KYC Vault</span>
            <div className="w-8 h-8 rounded-xl bg-blue-100 text-blue-700 flex items-center justify-center font-bold">
              <ShieldCheck size={16} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <h3 className="text-2xl font-black text-slate-900">{stats.masterKyc} / {MASTER_KYC_TYPES.length}</h3>
            <span className="text-[11px] font-bold text-blue-600">Verified</span>
          </div>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Shared identity documents</p>
        </div>

        {/* Stat 3: Project Workspaces */}
        <div 
          onClick={() => setActiveTab('workspaces')}
          className={`cursor-pointer rounded-2xl p-5 border transition-all transform hover:-translate-y-0.5 ${
            activeTab === 'workspaces' 
              ? 'bg-red-50/50 border-red-300 shadow-md ring-2 ring-red-500/20' 
              : 'bg-white border-slate-200/90 shadow-2xs hover:border-red-200'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Project Workspaces</span>
            <div className="w-8 h-8 rounded-xl bg-red-100 text-red-600 flex items-center justify-center font-bold">
              <FolderOpen size={16} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <h3 className="text-2xl font-black text-slate-900">{orders.length}</h3>
            <span className="text-[11px] font-bold text-red-600">Active</span>
          </div>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Engagements & order vaults</p>
        </div>

        {/* Stat 4: Pending Actions */}
        <div 
          onClick={() => setActiveTab('workspaces')}
          className={`cursor-pointer rounded-2xl p-5 border transition-all transform hover:-translate-y-0.5 ${
            stats.pendingRequirements > 0
              ? 'bg-amber-50/60 border-amber-300 shadow-2xs hover:border-amber-400'
              : 'bg-white border-slate-200/90 shadow-2xs'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Checklist Items</span>
            <div className={`w-8 h-8 rounded-xl flex items-center justify-center font-bold ${
              stats.pendingRequirements > 0 ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'
            }`}>
              {stats.pendingRequirements > 0 ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <h3 className="text-2xl font-black text-slate-900">{stats.pendingRequirements}</h3>
            <span className={`text-[11px] font-bold ${stats.pendingRequirements > 0 ? 'text-amber-600' : 'text-emerald-600'}`}>
              {stats.pendingRequirements > 0 ? 'Needs Attention' : 'All Clear'}
            </span>
          </div>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">Pending document requests</p>
        </div>
      </div>

      {/* 3. Primary Segmented Tab Navigation */}
      <div className="bg-slate-100/90 p-1.5 rounded-2xl border border-slate-200 flex gap-1.5 overflow-x-auto shadow-inner">
        {[
          { 
            key: 'provided', 
            label: 'Government Deliverables', 
            icon: FileCheck, 
            badge: stats.deliverables,
            badgeColor: 'bg-emerald-100 text-emerald-800'
          },
          { 
            key: 'master_kyc', 
            label: 'Master KYC Vault', 
            icon: ShieldCheck, 
            badge: `${stats.masterKyc}/${MASTER_KYC_TYPES.length}`,
            badgeColor: 'bg-blue-100 text-blue-800'
          },
          { 
            key: 'workspaces', 
            label: 'Project Workspaces', 
            icon: FolderOpen, 
            badge: orders.length,
            badgeColor: 'bg-red-100 text-red-800'
          },
          { 
            key: 'explorer', 
            label: 'All Vault Files', 
            icon: Layers, 
            badge: allFlattenedFiles.length,
            badgeColor: 'bg-slate-200 text-slate-800'
          }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex-1 py-3 px-4 rounded-xl text-xs font-black transition-all flex items-center justify-center gap-2 whitespace-nowrap ${
                isActive
                  ? 'bg-white text-slate-900 shadow-md border border-slate-200/80 scale-[1.01]'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <Icon size={16} className={isActive ? 'text-red-600' : 'text-slate-400'} />
              <span>{tab.label}</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-black tracking-wide ${tab.badgeColor}`}>
                {tab.badge}
              </span>
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: GOVERNMENT DELIVERABLES & CERTIFICATES */}
      {/* ========================================================================= */}
      {activeTab === 'provided' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {orders.some(o => o.finalCertificateUrl) ? (
            <div className="space-y-4">
              <div>
                <h3 className="text-base font-black text-slate-900 flex items-center gap-2">
                  <Sparkles size={18} className="text-amber-500" />
                  Official Incorporation & Government Certificates
                </h3>
                <p className="text-xs text-slate-500 font-medium">Verified by Ministry of Corporate Affairs / Respective Government Authorities</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {orders.filter(o => o.finalCertificateUrl).map(order => (
                  <div 
                    key={order._id}
                    className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-slate-850 to-slate-950 p-6 text-white border border-slate-800 shadow-xl flex flex-col justify-between space-y-4 group hover:border-emerald-500/50 transition-all"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3.5">
                        <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center font-black shrink-0">
                          <FileCheck size={24} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="px-2.5 py-0.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full text-[10px] font-black uppercase">
                              Official Final Certificate
                            </span>
                            <span className="text-[11px] text-slate-400">
                              #{order._id?.slice(-6).toUpperCase()}
                            </span>
                          </div>
                          <h4 className="text-base font-black text-white mt-1 group-hover:text-emerald-300 transition-colors">
                            {order.serviceName}
                          </h4>
                          <p className="text-xs text-slate-400 font-medium">Issued on {new Date(order.updatedAt || order.createdAt).toLocaleDateString()}</p>
                        </div>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-3">
                      <button
                        onClick={() => setPreviewDoc({ name: `${order.serviceName} - Final Certificate`, url: order.finalCertificateUrl })}
                        className="px-3.5 py-2 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1.5"
                      >
                        <Eye size={13} />
                        <span>Preview</span>
                      </button>

                      <a
                        href={order.finalCertificateUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        download
                        className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-xl text-xs font-black transition-all flex items-center gap-1.5 shadow-md shadow-emerald-600/20"
                      >
                        <Download size={14} />
                        <span>Download Certificate</span>
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {/* All Delivered Admin Documents across projects */}
          <div className="bg-white rounded-3xl p-6 sm:p-7 border border-slate-200/90 shadow-2xs space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
              <div>
                <h3 className="text-base font-black text-slate-900 flex items-center gap-2">
                  <FileCheck size={18} className="text-emerald-600" />
                  Government Filings, Challans & Deliverables
                </h3>
                <p className="text-xs text-slate-500 font-medium mt-0.5">
                  Official statutory acknowledgments, receipts, approval letters, and stamp papers uploaded by our compliance team.
                </p>
              </div>
              <span className="text-xs font-black px-3 py-1 bg-slate-100 text-slate-700 rounded-full self-start sm:self-auto">
                {allFlattenedFiles.filter(f => f.category === 'Government Deliverable').length} Total Deliverables
              </span>
            </div>

            {allFlattenedFiles.filter(f => f.category === 'Government Deliverable' && !f.isCertificate).length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {allFlattenedFiles.filter(f => f.category === 'Government Deliverable' && !f.isCertificate).map(doc => (
                  <div 
                    key={doc.id}
                    className="p-4 rounded-2xl border border-slate-200/80 bg-slate-50/50 hover:bg-white hover:border-slate-300 hover:shadow-md transition-all flex flex-col justify-between space-y-3"
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-10 h-10 rounded-xl bg-red-50 text-red-600 border border-red-200/80 flex items-center justify-center shrink-0">
                        <FileText size={18} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-black text-slate-900 truncate" title={doc.name}>
                          {doc.name}
                        </p>
                        <p className="text-[10px] text-slate-400 font-medium truncate mt-0.5">
                          {doc.source}
                        </p>
                        <span className="inline-block mt-1.5 px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-md text-[9.5px] font-bold">
                          Issued on {new Date(doc.date).toLocaleDateString()}
                        </span>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-slate-200/60 flex items-center justify-between gap-2">
                      <button
                        onClick={() => setPreviewDoc({ name: doc.name, url: doc.url })}
                        className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold transition-all flex items-center gap-1"
                      >
                        <Eye size={12} />
                        <span>Preview</span>
                      </button>

                      <a
                        href={doc.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 bg-slate-900 hover:bg-red-600 text-white rounded-lg text-xs font-bold transition-all flex items-center gap-1 shadow-2xs"
                      >
                        <ExternalLink size={12} />
                        <span>Open</span>
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400 bg-slate-50/50 rounded-2xl border border-dashed border-slate-200 space-y-2">
                <FolderOpen size={36} className="mx-auto text-slate-300" />
                <p className="text-xs font-bold text-slate-600">No Government Deliverables issued yet</p>
                <p className="text-[11px] text-slate-400 max-w-sm mx-auto">
                  Once your filings are approved by the government authority or ministry, official challans and certificates will automatically appear here.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: MASTER KYC & CORPORATE IDENTITY VAULT */}
      {/* ========================================================================= */}
      {activeTab === 'master_kyc' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="bg-gradient-to-r from-blue-900 via-indigo-900 to-slate-900 rounded-3xl p-6 text-white border border-blue-800 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
            <div className="space-y-1.5">
              <span className="px-3 py-0.5 bg-white/10 text-blue-200 text-[10px] font-black rounded-full uppercase tracking-wider">
                Upload Once • Auto-Apply to All Engagements
              </span>
              <h3 className="text-xl font-black text-white flex items-center gap-2.5">
                <ShieldCheck size={22} className="text-emerald-400" />
                Master Corporate & Director KYC Vault
              </h3>
              <p className="text-xs text-blue-200/90 max-w-2xl font-normal leading-relaxed">
                Save your standard company documents (PAN, Aadhaar, GSTIN, Incorporation, Cheque) securely to your dedicated Google Drive vault. Whenever you start a new engagement, these documents auto-populate instantly without re-uploading!
              </p>
            </div>

            <div className="px-4 py-3 bg-white/10 rounded-2xl border border-white/10 backdrop-blur-md shrink-0 text-center">
              <p className="text-[10px] font-black uppercase tracking-wider text-blue-200">Vault Health</p>
              <p className="text-2xl font-black text-white mt-0.5">
                {Math.round((vaultDocuments.length / MASTER_KYC_TYPES.length) * 100)}%
              </p>
              <p className="text-[10px] text-emerald-300 font-bold">{vaultDocuments.length} of {MASTER_KYC_TYPES.length} Verified</p>
            </div>
          </div>

          {/* Grid of Master Document Tiles */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {MASTER_KYC_TYPES.map((typeObj) => {
              const vaultDoc = vaultDocuments.find(d => d.docType === typeObj.id);
              const fallbackDoc = !vaultDoc ? getFallbackForMasterType(typeObj.id) : null;
              const doc = vaultDoc || fallbackDoc;
              const isUploading = uploadingDocType === typeObj.id;
              const fileUrl = vaultDoc?.gdriveWebViewLink || doc?.url;
              const Icon = typeObj.icon;

              return (
                <div
                  key={typeObj.id}
                  className={`rounded-3xl p-5 border transition-all flex flex-col justify-between space-y-4 ${
                    vaultDoc
                      ? 'bg-white border-slate-200/90 shadow-2xs hover:shadow-md hover:border-slate-300'
                      : fallbackDoc
                      ? 'bg-blue-50/30 border-blue-200 hover:bg-white hover:shadow-sm'
                      : 'bg-slate-50/70 border-dashed border-slate-300 hover:border-red-400 hover:bg-white'
                  }`}
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-2xl flex items-center justify-center shrink-0 ${
                          vaultDoc 
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                            : fallbackDoc
                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                            : 'bg-slate-100 text-slate-500'
                        }`}>
                          <Icon size={18} />
                        </div>
                        <div>
                          <h4 className="font-black text-slate-900 text-sm tracking-tight leading-snug">
                            {typeObj.label}
                          </h4>
                          <p className="text-[11px] text-slate-400 font-medium">
                            {typeObj.desc}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="p-3 bg-slate-50 rounded-xl border border-slate-100 flex items-center justify-between">
                      <div className="min-w-0 pr-2">
                        <p className="text-xs font-bold text-slate-800 truncate">
                          {vaultDoc ? vaultDoc.fileName : fallbackDoc ? fallbackDoc.name : 'No file uploaded'}
                        </p>
                        <p className="text-[10px] text-slate-400 mt-0.5">
                          {vaultDoc 
                            ? `Synced to G-Drive on ${new Date(vaultDoc.createdAt).toLocaleDateString()}` 
                            : fallbackDoc 
                            ? `Found from ${fallbackDoc.source}` 
                            : 'Action needed'}
                        </p>
                      </div>

                      {vaultDoc ? (
                        <span className="px-2.5 py-1 bg-emerald-100 text-emerald-800 rounded-full text-[9.5px] font-black uppercase tracking-wider flex items-center gap-1 shrink-0">
                          <CheckCircle2 size={11} /> Verified
                        </span>
                      ) : fallbackDoc ? (
                        <span className="px-2.5 py-1 bg-blue-100 text-blue-800 rounded-full text-[9.5px] font-bold uppercase tracking-wider shrink-0">
                          From Order
                        </span>
                      ) : (
                        <span className="px-2.5 py-1 bg-rose-100 text-rose-700 rounded-full text-[9.5px] font-bold uppercase tracking-wider shrink-0">
                          Missing
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-100 flex items-center justify-between gap-2">
                    {fileUrl ? (
                      <div className="flex items-center gap-2 w-full justify-between">
                        <button
                          onClick={() => setPreviewDoc({ name: typeObj.label, url: fileUrl })}
                          className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5"
                        >
                          <Eye size={13} />
                          <span>Preview</span>
                        </button>

                        <div className="flex items-center gap-1">
                          <label 
                            className={`p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl cursor-pointer transition-all ${
                              isUploading ? 'opacity-50 pointer-events-none' : ''
                            }`}
                            title="Upload / Replace with new file in Google Drive"
                          >
                            <Upload size={14} />
                            <input
                              type="file"
                              className="hidden"
                              disabled={isUploading}
                              onChange={(e) => e.target.files?.[0] && handleUploadMasterKyc(typeObj.id, e.target.files[0])}
                            />
                          </label>

                          {vaultDoc && (
                            <button
                              onClick={() => handleDeleteMasterKyc(vaultDoc._id)}
                              className="p-2 bg-rose-50 text-rose-600 hover:bg-rose-600 hover:text-white rounded-xl transition-all"
                              title="Delete from Master Vault"
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <label 
                        className={`w-full py-2.5 px-4 bg-slate-900 hover:bg-red-600 text-white rounded-xl text-xs font-bold cursor-pointer transition-all flex items-center justify-center gap-2 shadow-sm ${
                          isUploading ? 'opacity-50 pointer-events-none' : ''
                        }`}
                      >
                        <Upload size={14} />
                        <span>{isUploading ? 'Uploading to Drive...' : `Upload ${typeObj.id}`}</span>
                        <input
                          type="file"
                          className="hidden"
                          disabled={isUploading}
                          onChange={(e) => e.target.files?.[0] && handleUploadMasterKyc(typeObj.id, e.target.files[0])}
                        />
                      </label>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: PROJECT WORKSPACES & ORDER SPECIFIC FILINGS */}
      {/* ========================================================================= */}
      {activeTab === 'workspaces' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {orders.length > 0 ? (
            <div className="bg-white rounded-3xl p-6 border border-slate-200/90 shadow-2xs space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-slate-400">Select Project Engagement</p>
                  <h3 className="text-xl font-black text-slate-900 tracking-tight flex items-center gap-2.5">
                    <span>{selectedOrder?.serviceName || 'Active Workspace'}</span>
                    <span className="px-2.5 py-0.5 bg-red-50 text-red-600 border border-red-200/80 rounded-full text-xs font-black uppercase">
                      {selectedOrder?.status || 'Active'}
                    </span>
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500 font-bold bg-slate-100 px-3 py-1.5 rounded-xl">
                    Order ID: #{String(selectedOrder?._id).slice(-6).toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Horizontally scrollable project pills */}
              <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-none pt-2 border-t border-slate-100">
                {orders.map((order) => (
                  <button
                    key={order._id}
                    onClick={() => setSelectedOrderId(order._id)}
                    className={`px-4 py-2.5 rounded-xl text-xs font-bold whitespace-nowrap transition-all border shrink-0 flex items-center gap-2 ${
                      selectedOrder?._id === order._id
                        ? 'bg-slate-900 text-white border-slate-900 shadow-md scale-[1.01]'
                        : 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    <FolderOpen size={14} className={selectedOrder?._id === order._id ? 'text-red-400' : 'text-slate-400'} />
                    <span>{order.serviceName}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase ${
                      selectedOrder?._id === order._id ? 'bg-white/20 text-white' : 'bg-slate-200 text-slate-600'
                    }`}>
                      {order.status || 'Active'}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          {/* Active Workspace View */}
          {selectedOrder ? (
            <div className="space-y-6">
              {selectedOrder.serviceName?.toLowerCase().includes('income tax') || selectedOrder.packageName?.toLowerCase().includes('itr') ? (
                <ITRAssessmentCustomerView selectedOrder={selectedOrder} userInfo={userInfo} />
              ) : (
                <div className="space-y-6">
                  {/* Requirements & Checklist View */}
                  <div className="bg-white rounded-3xl p-6 sm:p-7 border border-slate-200/90 shadow-2xs">
                    <RequirementsWorkspace 
                      selectedOrder={selectedOrder} 
                      userInfo={userInfo} 
                      refreshOrders={refreshOrders} 
                    />
                  </div>

                  {/* Drag-and-Drop Direct Project File Uploader */}
                  <div className="bg-white rounded-3xl p-6 sm:p-7 border border-slate-200/90 shadow-2xs space-y-6">
                    <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                      <div>
                        <h4 className="text-base font-black text-slate-900 flex items-center gap-2">
                          <Upload size={18} className="text-red-600" />
                          Project Attachments & Custom Uploads
                        </h4>
                        <p className="text-xs text-slate-500 font-medium">Upload supporting documents, agreements, or receipts specifically for {selectedOrder.serviceName}.</p>
                      </div>
                    </div>

                    <div
                      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                      onDragLeave={() => setIsDragging(false)}
                      onDrop={(e) => {
                        e.preventDefault();
                        setIsDragging(false);
                        if (e.dataTransfer.files) {
                          setStagedFiles(Array.from(e.dataTransfer.files));
                        }
                      }}
                      className={`rounded-2xl p-6 border-2 border-dashed transition-all text-center space-y-3 ${
                        isDragging ? 'border-red-500 bg-red-50/20' : 'border-slate-300 hover:border-red-400 bg-slate-50/40'
                      }`}
                    >
                      <div className="w-12 h-12 rounded-2xl bg-red-50 text-red-600 border border-red-200 flex items-center justify-center mx-auto">
                        <Upload size={22} />
                      </div>
                      <div>
                        <h5 className="text-sm font-black text-slate-900">Drag and drop files here, or click to browse</h5>
                        <p className="text-xs text-slate-500 font-medium mt-0.5">Supports PDF, PNG, JPG, ZIP, XLSX (Max 25MB per file)</p>
                      </div>

                      <input
                        type="file"
                        id="workspace-file-input"
                        multiple
                        onChange={(e) => setStagedFiles(Array.from(e.target.files || []))}
                        className="hidden"
                      />
                      <label
                        htmlFor="workspace-file-input"
                        className="inline-flex items-center gap-2 px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold cursor-pointer transition-all shadow-sm"
                      >
                        <Plus size={14} />
                        <span>Select Files</span>
                      </label>

                      {stagedFiles.length > 0 && (
                        <div className="mt-5 pt-4 border-t border-slate-200 space-y-3">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-black text-slate-800 uppercase tracking-wider">
                              Files Staged for Upload ({stagedFiles.length})
                            </span>
                            <button
                              onClick={handleUploadOrderFiles}
                              disabled={isUploadingOrderDocs}
                              className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs px-4 py-2 rounded-xl transition-all shadow-md disabled:opacity-50 flex items-center gap-1.5"
                            >
                              <Upload size={13} />
                              <span>{isUploadingOrderDocs ? (orderUploadStatus || 'Uploading...') : 'Upload to Project'}</span>
                            </button>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-left">
                            {stagedFiles.map((file, idx) => (
                              <div key={idx} className="p-3 bg-white rounded-xl border border-slate-200 flex items-center justify-between text-xs shadow-2xs">
                                <span className="font-bold text-slate-800 truncate max-w-[200px]">{file.name}</span>
                                <button
                                  type="button"
                                  onClick={() => setStagedFiles(prev => prev.filter((_, i) => i !== idx))}
                                  className="text-red-600 hover:text-red-800 font-black text-[11px] uppercase ml-2"
                                >
                                  Remove
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {(selectedOrder.clientDocuments || []).length > 0 ? (
                      <div className="space-y-3">
                        <h5 className="text-xs font-black uppercase tracking-wider text-slate-400">
                          Uploaded Files ({selectedOrder.clientDocuments.length})
                        </h5>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {selectedOrder.clientDocuments.map((doc) => (
                            <div key={doc._id} className="bg-slate-50/70 p-4 rounded-2xl border border-slate-200 flex items-center justify-between gap-3">
                              <div className="flex items-center gap-3 min-w-0">
                                <div className="w-10 h-10 bg-white text-slate-700 border border-slate-200 rounded-xl flex items-center justify-center shrink-0">
                                  <FileText size={18} />
                                </div>
                                <div className="min-w-0">
                                  <p className="font-bold text-xs text-slate-900 truncate">{doc.name || doc.filename}</p>
                                  <p className="text-[10px] text-slate-400 font-medium">Uploaded on {new Date(doc.uploadedAt || Date.now()).toLocaleDateString()}</p>
                                </div>
                              </div>
                              <div className="flex items-center gap-1.5 shrink-0">
                                <button
                                  onClick={() => setPreviewDoc({ name: doc.name || doc.filename, url: doc.url || doc.path })}
                                  className="p-2 bg-white hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold transition-all"
                                  title="Preview"
                                >
                                  <Eye size={13} />
                                </button>
                                <a
                                  href={doc.url || doc.path}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="p-2 bg-slate-900 hover:bg-red-600 text-white rounded-lg text-xs font-bold transition-all"
                                  title="Download / Open"
                                >
                                  <Download size={13} />
                                </a>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-white rounded-3xl p-12 text-center text-slate-400 border border-slate-200 shadow-2xs space-y-3">
              <FolderOpen size={40} className="mx-auto text-slate-300" />
              <h4 className="text-sm font-bold text-slate-700">No active project engagements</h4>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">Start a new compliance, registration, or tax service to access project-specific checklists.</p>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: MASTER FILE EXPLORER (SEARCHABLE ACROSS ALL VAULTS) */}
      {/* ========================================================================= */}
      {activeTab === 'explorer' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="bg-white rounded-3xl p-5 border border-slate-200/90 shadow-2xs flex flex-col md:flex-row gap-4 justify-between items-center">
            <div className="relative w-full md:w-96">
              <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search across all files, certificates, orders..."
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-200 text-xs font-medium text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all bg-slate-50/50 focus:bg-white"
              />
            </div>

            <div className="flex gap-1.5 overflow-x-auto w-full md:w-auto pb-1 sm:pb-0">
              {[
                { key: 'ALL', label: 'All Files' },
                { key: 'Government Deliverable', label: 'Deliverables' },
                { key: 'Master KYC', label: 'Master KYC' },
                { key: 'Client Upload', label: 'My Uploads' },
                { key: 'Checklist Upload', label: 'Checklist Items' }
              ].map(cat => (
                <button
                  key={cat.key}
                  onClick={() => setFilterCategory(cat.key)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold whitespace-nowrap transition-all ${
                    filterCategory === cat.key
                      ? 'bg-slate-900 text-white shadow-2xs'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-3xl border border-slate-200/90 shadow-2xs overflow-hidden">
            {explorerFilteredFiles.length > 0 ? (
              <div className="divide-y divide-slate-100">
                {explorerFilteredFiles.map((file) => (
                  <div 
                    key={file.id} 
                    className="p-4 sm:p-5 hover:bg-slate-50/80 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="flex items-center gap-3.5 min-w-0">
                      <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                        file.category === 'Government Deliverable'
                          ? 'bg-emerald-50 text-emerald-600 border border-emerald-200'
                          : file.category === 'Master KYC'
                          ? 'bg-blue-50 text-blue-600 border border-blue-200'
                          : 'bg-slate-100 text-slate-600 border border-slate-200'
                      }`}>
                        {file.category === 'Government Deliverable' ? <FileCheck size={18} /> : <FileText size={18} />}
                      </div>

                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="font-black text-xs sm:text-sm text-slate-900 truncate" title={file.name}>
                            {file.name}
                          </p>
                          <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider shrink-0 ${
                            file.category === 'Government Deliverable'
                              ? 'bg-emerald-100 text-emerald-800'
                              : file.category === 'Master KYC'
                              ? 'bg-blue-100 text-blue-800'
                              : 'bg-slate-200 text-slate-700'
                          }`}>
                            {file.category}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 text-[11px] text-slate-400 font-medium mt-0.5">
                          <span>{file.source}</span>
                          <span>•</span>
                          <span>{new Date(file.date).toLocaleDateString()}</span>
                          <span>•</span>
                          <span className="text-emerald-600 font-bold">{file.status}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                      <button
                        onClick={() => setPreviewDoc({ name: file.name, url: file.url })}
                        className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold transition-all flex items-center gap-1"
                      >
                        <Eye size={12} />
                        <span>Preview</span>
                      </button>

                      <a
                        href={file.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 bg-slate-900 hover:bg-red-600 text-white rounded-lg text-xs font-bold transition-all flex items-center gap-1 shadow-2xs"
                      >
                        <Download size={12} />
                        <span>Download</span>
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-12 text-center text-slate-400 space-y-2">
                <Search size={36} className="mx-auto text-slate-300" />
                <p className="text-xs font-bold text-slate-600">No documents matched your search filter</p>
                <p className="text-[11px] text-slate-400">Try changing the keywords or selecting 'All Files'.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* UNIVERSAL ENHANCED DOCUMENT PREVIEW MODAL */}
      {/* ========================================================================= */}
      {previewDoc && (() => {
        const docInfo = parseDocInfo(previewDoc.url, previewDoc.name);
        return (
          <div 
            className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200"
            onClick={() => setPreviewDoc(null)}
          >
            <div 
              className="w-full max-w-4xl h-[85vh] bg-white rounded-3xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col animate-in zoom-in-95 duration-200"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="px-6 py-4 bg-slate-900 text-white flex items-center justify-between shrink-0">
                <div className="flex items-center gap-3 min-w-0 pr-4">
                  <div className="w-9 h-9 rounded-xl bg-red-600 flex items-center justify-center text-white font-bold shrink-0">
                    {docInfo.type === 'spreadsheet' ? <FileSpreadsheet size={18} /> : <FileText size={18} />}
                  </div>
                  <div className="min-w-0">
                    <h4 className="font-black text-sm text-white truncate">{previewDoc.name}</h4>
                    <p className="text-[10px] text-slate-400 flex items-center gap-1.5">
                      <span>Secure Document Viewer</span>
                      <span className="px-1.5 py-0.2 bg-white/10 text-slate-300 rounded text-[9px] font-bold uppercase">{docInfo.ext}</span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href={docInfo.rawUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1"
                  >
                    <ExternalLink size={12} />
                    <span>Open in New Tab</span>
                  </a>
                  <a
                    href={docInfo.rawUrl}
                    download
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1 shadow-sm"
                  >
                    <Download size={12} />
                    <span>Download</span>
                  </a>
                  <button
                    onClick={() => setPreviewDoc(null)}
                    className="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition ml-1"
                  >
                    <X size={18} />
                  </button>
                </div>
              </div>

              {/* Modal Viewer Content */}
              <div className="flex-1 bg-slate-100 overflow-hidden relative flex flex-col items-center justify-center">
                {/* 1. Image Viewer */}
                {docInfo.type === 'image' ? (
                  <div className="w-full h-full p-4 flex items-center justify-center overflow-auto bg-slate-900/10">
                    <img 
                      src={docInfo.rawUrl} 
                      alt={previewDoc.name} 
                      className="max-h-full max-w-full object-contain rounded-xl shadow-lg border border-white"
                    />
                  </div>
                ) : docInfo.type === 'spreadsheet' ? (
                  /* 2. Spreadsheet Showcase Card */
                  <div className="p-8 max-w-md w-full mx-auto text-center space-y-5 bg-white rounded-3xl border border-slate-200 shadow-xl m-4 animate-in zoom-in-95">
                    <div className="w-16 h-16 rounded-3xl bg-emerald-50 text-emerald-600 border border-emerald-200 flex items-center justify-center mx-auto shadow-inner">
                      <FileSpreadsheet size={32} />
                    </div>
                    <div>
                      <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-800 rounded-full text-[10px] font-black uppercase tracking-wider">
                        Microsoft Excel / Spreadsheet
                      </span>
                      <h4 className="text-base font-black text-slate-900 mt-2 truncate max-w-xs mx-auto">
                        {previewDoc.name}
                      </h4>
                      <p className="text-xs text-slate-500 font-medium mt-1">
                        Spreadsheets (.xlsx, .csv) are secured and ready for download or opening in Google Sheets / Excel.
                      </p>
                    </div>

                    <div className="flex flex-col gap-2.5 pt-2">
                      <a
                        href={docInfo.rawUrl}
                        download
                        className="w-full py-3 px-4 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-black transition-all flex items-center justify-center gap-2 shadow-md shadow-emerald-600/25"
                      >
                        <Download size={14} />
                        <span>Download Spreadsheet (.xlsx)</span>
                      </a>
                      <a
                        href={docInfo.rawUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="w-full py-2.5 px-4 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2"
                      >
                        <ExternalLink size={13} />
                        <span>Open / Preview in Google Sheets</span>
                      </a>
                    </div>
                  </div>
                ) : docInfo.type === 'word' ? (
                  /* 3. Word Document Card */
                  <div className="p-8 max-w-md w-full mx-auto text-center space-y-5 bg-white rounded-3xl border border-slate-200 shadow-xl m-4 animate-in zoom-in-95">
                    <div className="w-16 h-16 rounded-3xl bg-blue-50 text-blue-600 border border-blue-200 flex items-center justify-center mx-auto shadow-inner">
                      <FileText size={32} />
                    </div>
                    <div>
                      <span className="px-2.5 py-0.5 bg-blue-100 text-blue-800 rounded-full text-[10px] font-black uppercase tracking-wider">
                        Word Document
                      </span>
                      <h4 className="text-base font-black text-slate-900 mt-2 truncate max-w-xs mx-auto">
                        {previewDoc.name}
                      </h4>
                      <p className="text-xs text-slate-500 font-medium mt-1">
                        Word documents (.docx) can be downloaded or viewed in your local Office suite.
                      </p>
                    </div>

                    <div className="flex flex-col gap-2.5 pt-2">
                      <a
                        href={docInfo.rawUrl}
                        download
                        className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-black transition-all flex items-center justify-center gap-2 shadow-md shadow-blue-600/25"
                      >
                        <Download size={14} />
                        <span>Download Document (.docx)</span>
                      </a>
                      <a
                        href={docInfo.rawUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="w-full py-2.5 px-4 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2"
                      >
                        <ExternalLink size={13} />
                        <span>Open in New Window</span>
                      </a>
                    </div>
                  </div>
                ) : (
                  /* 4. PDF / Google Drive / Generic Embeddable Frame with Fallback Bar */
                  <div className="w-full h-full relative flex flex-col">
                    <iframe
                      src={docInfo.embedUrl}
                      title={previewDoc.name}
                      className="w-full flex-1 border-none bg-white"
                      allow="autoplay; encrypted-media"
                    />
                    <div className="bg-slate-900/90 backdrop-blur-md px-4 py-2 flex items-center justify-between text-xs text-slate-300 border-t border-slate-800">
                      <span>Document not rendering directly?</span>
                      <div className="flex items-center gap-2">
                        <a
                          href={docInfo.rawUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white rounded-lg font-bold flex items-center gap-1"
                        >
                          <ExternalLink size={12} /> Open in New Tab
                        </a>
                        <a
                          href={docInfo.rawUrl}
                          download
                          className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded-lg font-bold flex items-center gap-1"
                        >
                          <Download size={12} /> Direct Download
                        </a>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

    </div>
  );
};

export default DocumentsView;
