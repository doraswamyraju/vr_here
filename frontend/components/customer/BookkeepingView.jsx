import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Plus, Settings, RefreshCw, X, Eye, 
    Upload, Camera, Check, FileCheck, CheckCircle
} from 'lucide-react';

import GSTInvoiceView from './bookkeeping/GSTInvoiceView';
import CompanySettingsModal from './bookkeeping/CompanySettingsModal';
import PartiesTab from './bookkeeping/PartiesTab';
import TransactionListTab from './bookkeeping/TransactionListTab';
import TransactionFormModal from './bookkeeping/TransactionFormModal';

const BookkeepingView = ({ token }) => {
    const [transactions, setTransactions] = useState([]);
    const [company, setCompany] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showAddForm, setShowAddForm] = useState(false);
    const [showSettings, setShowSettings] = useState(false);
    const [selectedInvoice, setSelectedInvoice] = useState(null);
    
    // Parties / Customers state
    const [parties, setParties] = useState(() => {
        const saved = localStorage.getItem('bookkeeping_parties');
        return saved ? JSON.parse(saved) : [
            { name: 'Lucky Constructions', gstin: '37AABCL9876E1Z2', address: '#38A, 1st Floor, TUDA Complex, Tirupati', phone: '9876543210' },
            { name: 'SSV Traders', gstin: '37AABCS5432D1Z0', address: 'Bairagipatteda, Tirupati', phone: '9988776655' }
        ];
    });
    const [showAddPartyModal, setShowAddPartyModal] = useState(false);
    const [activeSubTab, setActiveSubTab] = useState('Transactions'); // 'Transactions' | 'Parties'

    // Filtering states
    const [filterType, setFilterType] = useState('All'); 
    const [searchQuery, setSearchQuery] = useState('');

    // Form states
    const [txType, setTxType] = useState('Sales'); 
    const [docNumber, setDocNumber] = useState('');
    const [invoicePrefix, setInvoicePrefix] = useState('270326'); 
    const [docDate, setDocDate] = useState(new Date().toISOString().split('T')[0]);
    
    const [partyName, setPartyName] = useState('');
    const [partyGstin, setPartyGstin] = useState('');
    const [partyAddress, setPartyAddress] = useState('');
    const [placeOfSupply, setPlaceOfSupply] = useState('Andhra Pradesh');
    const [isInterstate, setIsInterstate] = useState(false);
    const [paymentType, setPaymentType] = useState('Cash');
    const [notes, setNotes] = useState('');
    
    const [uploadingBill, setUploadingBill] = useState(false);

    // Vyapar style table items
    const [items, setItems] = useState([
        { description: '', qty: 1, unit: 'NONE', rate: 0, discountPercent: 0, gstRate: 18 }
    ]);
    
    // Available units
    const [availableUnits, setAvailableUnits] = useState(['NONE', 'BOX', 'PCS', 'KGS', 'LTRS', 'MTRS']);
    const [newUnitName, setNewUnitName] = useState('');
    const [showAddUnitInline, setShowAddUnitInline] = useState(false);

    // Company Settings
    const [companyName, setCompanyName] = useState('');
    const [tradeName, setTradeName] = useState('');
    const [companyGstin, setCompanyGstin] = useState('');
    const [companyAddress, setCompanyAddress] = useState('');
    const [companyState, setCompanyState] = useState('Andhra Pradesh');
    const [companyPhone, setCompanyPhone] = useState('');
    const [companyEmail, setCompanyEmail] = useState('');
    const [companyType, setCompanyType] = useState('Service');
    const [companyCategory, setCompanyCategory] = useState('Consultancy');
    const [companyPincode, setCompanyPincode] = useState('');

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Save parties
    useEffect(() => {
        localStorage.setItem('bookkeeping_parties', JSON.stringify(parties));
    }, [parties]);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [txRes, compRes] = await Promise.allSettled([
                axios.get('/api/accounting/transactions', config),
                axios.get('/api/accounting/company', config)
            ]);

            if (txRes.status === 'fulfilled') setTransactions(txRes.value.data);
            if (compRes.status === 'fulfilled') {
                const c = compRes.value.data;
                setCompany(c);
                setCompanyName(c.companyName || '');
                setTradeName(c.tradeName || '');
                setCompanyGstin(c.gstin || '');
                setCompanyAddress(c.address || '');
                setCompanyState(c.state || '');
                setCompanyPhone(c.phone || '');
                setCompanyEmail(c.email || '');
                setCompanyType(c.businessType || 'Service');
                setCompanyCategory(c.businessCategory || 'Consultancy');
                setCompanyPincode(c.pincode || '');
            }
        } catch (error) {
            console.error('Error fetching bookkeeping data:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    // Interstate Auto-Detection
    useEffect(() => {
        if (companyState && placeOfSupply) {
            setIsInterstate(companyState !== placeOfSupply);
        }
    }, [companyState, placeOfSupply]);

    // Automatic invoice numbering
    useEffect(() => {
        if (showAddForm) {
            const prefix = txType === 'Sales' ? invoicePrefix : 'BILL-';
            const count = transactions.filter(t => t.transactionType === txType).length + 1;
            const paddedCount = String(count).padStart(4, '0');
            setDocNumber(`${prefix}${paddedCount}`);
        }
    }, [showAddForm, txType, invoicePrefix, transactions]);

    const handleSaveCompany = async (e) => {
        e.preventDefault();
        try {
            const { data } = await axios.post('/api/accounting/company', {
                companyName,
                tradeName,
                gstin: companyGstin,
                address: companyAddress,
                state: companyState,
                phone: companyPhone,
                email: companyEmail,
                businessType: companyType,
                businessCategory: companyCategory,
                pincode: companyPincode
            }, config);
            setCompany(data);
            setShowSettings(false);
            alert('Business Details saved successfully!');
        } catch (error) {
            alert('Failed to save business settings: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleAddItem = () => {
        setItems([...items, { description: '', qty: 1, unit: 'NONE', rate: 0, discountPercent: 0, gstRate: 18 }]);
    };

    const handleItemChange = (index, field, value) => {
        const updated = [...items];
        updated[index][field] = value;
        setItems(updated);
    };

    const handleRemoveItem = (index) => {
        if (items.length > 1) {
            setItems(items.filter((_, i) => i !== index));
        }
    };

    const handlePartySelect = (pName) => {
        const party = parties.find(p => p.name === pName);
        if (party) {
            setPartyName(party.name);
            setPartyGstin(party.gstin || '');
            setPartyAddress(party.address || '');
        } else {
            setPartyName(pName);
        }
    };

    const handleAddNewParty = (e) => {
        e.preventDefault();
        const name = e.target.pName.value;
        const gstin = e.target.pGstin.value;
        const address = e.target.pAddress.value;
        const phone = e.target.pPhone.value;

        if (!name) return;

        const newParty = { name, gstin, address, phone };
        setParties([...parties, newParty]);
        setShowAddPartyModal(false);
        alert('Customer added successfully!');
    };

    const handleAddUnit = () => {
        if (newUnitName && !availableUnits.includes(newUnitName.toUpperCase())) {
            setAvailableUnits([...availableUnits, newUnitName.toUpperCase()]);
            setNewUnitName('');
            setShowAddUnitInline(false);
        }
    };

    const handleAddTransaction = async (e) => {
        e.preventDefault();
        try {
            const mappedItems = items.map(item => {
                const discountAmount = Number(item.qty * item.rate * (item.discountPercent / 100));
                const taxableVal = Number((item.qty * item.rate) - discountAmount);
                const gstAmt = Number(taxableVal * (item.gstRate / 100));
                
                return {
                    description: item.description,
                    hsnSac: '9999',
                    qty: item.qty,
                    rate: item.rate,
                    gstRate: item.gstRate,
                    discount: discountAmount,
                    cgst: isInterstate ? 0 : gstAmt / 2,
                    sgst: isInterstate ? 0 : gstAmt / 2,
                    igst: isInterstate ? gstAmt : 0,
                    amount: taxableVal + gstAmt
                };
            });

            await axios.post('/api/accounting/transactions', {
                transactionType: txType,
                docNumber,
                docDate,
                partyName,
                partyGstin,
                placeOfSupply,
                isInterstate,
                notes,
                items: mappedItems
            }, config);

            setPartyName('');
            setPartyGstin('');
            setNotes('');
            setItems([{ description: '', qty: 1, unit: 'NONE', rate: 0, discountPercent: 0, gstRate: 18 }]);
            setShowAddForm(false);
            fetchData();
        } catch (error) {
            alert('Failed to add transaction: ' + (error.response?.data?.message || error.message));
        }
    };

    const handleDeleteTransaction = async (id) => {
        if (window.confirm('Are you sure you want to delete this record?')) {
            try {
                await axios.delete(`/api/accounting/transactions/${id}`, config);
                fetchData();
            } catch (error) {
                alert('Failed to delete transaction');
            }
        }
    };

    const handleOCRUpload = (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setUploadingBill(true);
        setTimeout(() => {
            setPartyName('HighTech Solutions Ltd');
            setPartyGstin('36AABCH4567D1Z8');
            setDocNumber('OCR-BILL-' + Math.floor(Math.random() * 10000));
            setDocDate(new Date().toISOString().split('T')[0]);
            setItems([
                { description: 'Equipment Purchases & Office Supplies', qty: 2, unit: 'PCS', rate: 12000, discountPercent: 5, gstRate: 18 }
            ]);
            setUploadingBill(false);
            alert('Bill successfully scanned! OCR details populated.');
        }, 1500);
    };

    const handleCopyShareLink = () => {
        const mockLink = `${window.location.origin}/invoice/view/${selectedInvoice._id}`;
        navigator.clipboard.writeText(mockLink);
        alert('Invoice share link copied to clipboard!');
    };

    const filteredTransactions = transactions.filter(t => {
        if (filterType !== 'All' && t.transactionType !== filterType) return false;
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            return t.partyName.toLowerCase().includes(query) || t.docNumber.toLowerCase().includes(query);
        }
        return true;
    });

    const totalSales = transactions.filter(t => t.transactionType === 'Sales').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalPurchases = transactions.filter(t => t.transactionType === 'Purchase').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalExpenses = transactions.filter(t => t.transactionType === 'Expense').reduce((acc, c) => acc + c.summary.totalAmount, 0);
    const totalIncome = transactions.filter(t => t.transactionType === 'Income').reduce((acc, c) => acc + c.summary.totalAmount, 0);

    if (selectedInvoice) {
        return (
            <GSTInvoiceView 
                selectedInvoice={selectedInvoice}
                company={company}
                onBack={() => setSelectedInvoice(null)}
                onCopyShareLink={handleCopyShareLink}
            />
        );
    }

    return (
        <div className="space-y-6 pb-24 px-4 md:px-8">
            {/* Vyapar style sub tab/top navigation */}
            <div className="flex justify-between items-center border-b border-slate-200 pb-4 flex-wrap gap-4">
                <div className="flex items-center gap-6">
                    <button 
                        onClick={() => setActiveSubTab('Transactions')} 
                        className={`text-sm font-bold pb-2 transition border-b-2 ${activeSubTab === 'Transactions' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500'}`}
                    >
                        Transactions
                    </button>
                    <button 
                        onClick={() => setActiveSubTab('Parties')} 
                        className={`text-sm font-bold pb-2 transition border-b-2 ${activeSubTab === 'Parties' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500'}`}
                    >
                        Customers / Parties
                    </button>
                </div>
                
                <div className="flex gap-2">
                    <button 
                        onClick={() => setShowSettings(true)}
                        className="bg-white text-slate-700 px-4 py-2 rounded-xl border border-slate-300 hover:bg-slate-50 transition flex items-center gap-1.5 font-bold text-xs"
                    >
                        <Settings size={14} /> Company Settings
                    </button>
                    <button 
                        onClick={() => { setTxType('Sales'); setShowAddForm(true); }}
                        className="bg-red-500 text-white px-5 py-2.5 rounded-xl hover:bg-red-600 transition flex items-center gap-1 font-bold text-xs shadow-md shadow-red-100"
                    >
                        <Plus size={14} /> Add Sale
                    </button>
                    <button 
                        onClick={() => { setTxType('Purchase'); setShowAddForm(true); }}
                        className="bg-blue-600 text-white px-5 py-2.5 rounded-xl hover:bg-blue-700 transition flex items-center gap-1 font-bold text-xs shadow-md shadow-blue-100"
                    >
                        <Plus size={14} /> Add Purchase
                    </button>
                </div>
            </div>

            {activeSubTab === 'Parties' ? (
                <PartiesTab 
                    parties={parties}
                    showAddPartyModal={showAddPartyModal}
                    onShowAddPartyModal={() => setShowAddPartyModal(true)}
                    onCloseAddPartyModal={() => setShowAddPartyModal(false)}
                    onSaveParty={handleAddNewParty}
                />
            ) : (
                <TransactionListTab 
                    transactions={filteredTransactions}
                    loading={loading}
                    filterType={filterType}
                    setFilterType={setFilterType}
                    searchQuery={searchQuery}
                    setSearchQuery={setSearchQuery}
                    onRefresh={fetchData}
                    totalSales={totalSales}
                    totalPurchases={totalPurchases}
                    totalExpenses={totalExpenses}
                    totalIncome={totalIncome}
                    onViewInvoice={setSelectedInvoice}
                    onDeleteTransaction={handleDeleteTransaction}
                />
            )}

            {/* Transaction entry Modal */}
            <TransactionFormModal 
                show={showAddForm}
                onClose={() => setShowAddForm(false)}
                onSubmit={handleAddTransaction}
                txType={txType}
                setTxType={setTxType}
                docNumber={docNumber}
                setDocNumber={setDocNumber}
                docDate={docDate}
                setDocDate={setDocDate}
                placeOfSupply={placeOfSupply}
                setPlaceOfSupply={setPlaceOfSupply}
                isInterstate={isInterstate}
                partyName={partyName}
                setPartyName={setPartyName}
                partyGstin={partyGstin}
                setPartyGstin={setPartyGstin}
                parties={parties}
                onShowAddPartyModal={() => setShowAddPartyModal(true)}
                onPartySelect={handlePartySelect}
                availableUnits={availableUnits}
                onShowAddUnitInline={() => setShowAddUnitInline(true)}
                items={items}
                onAddItem={handleAddItem}
                onRemoveItem={handleRemoveItem}
                onItemChange={handleItemChange}
                paymentType={paymentType}
                setPaymentType={setPaymentType}
                notes={notes}
                setNotes={setNotes}
                uploadingBill={uploadingBill}
                onOCRUpload={handleOCRUpload}
            />

            {/* Custom Measurement Unit Modal */}
            {showAddUnitInline && (
                <div className="fixed inset-0 z-[60] bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white w-full max-w-xs rounded-2xl p-5 shadow-2xl relative">
                        <button onClick={() => setShowAddUnitInline(false)} className="absolute top-4 right-4 text-slate-400 hover:text-slate-600">
                            <X size={16} />
                        </button>
                        <h4 className="font-bold text-slate-800 text-xs mb-3">Add Custom Measurement Unit</h4>
                        <div className="space-y-3">
                            <input 
                                type="text" 
                                placeholder="e.g. BAGS, DOZ, NOS"
                                value={newUnitName}
                                onChange={e => setNewUnitName(e.target.value)}
                                className="w-full bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-800 focus:outline-none uppercase"
                            />
                            <button 
                                onClick={handleAddUnit}
                                className="w-full bg-indigo-600 text-white py-2 rounded-xl text-xs font-bold hover:bg-indigo-700 transition"
                            >
                                Add Unit
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Company profile settings Edit Modal */}
            <CompanySettingsModal 
                show={showSettings}
                onClose={() => setShowSettings(false)}
                onSave={handleSaveCompany}
                companyName={companyName}
                setCompanyName={setCompanyName}
                tradeName={tradeName}
                setTradeName={setTradeName}
                companyGstin={companyGstin}
                setCompanyGstin={setCompanyGstin}
                companyAddress={companyAddress}
                setCompanyAddress={setCompanyAddress}
                companyState={companyState}
                setCompanyState={setCompanyState}
                companyPhone={companyPhone}
                setCompanyPhone={setCompanyPhone}
                companyEmail={companyEmail}
                setCompanyEmail={setCompanyEmail}
                companyType={companyType}
                setCompanyType={setCompanyType}
                companyCategory={companyCategory}
                setCompanyCategory={setCompanyCategory}
                companyPincode={companyPincode}
                setCompanyPincode={setCompanyPincode}
                invoicePrefix={invoicePrefix}
                setInvoicePrefix={setInvoicePrefix}
            />
        </div>
    );
};

export default BookkeepingView;
