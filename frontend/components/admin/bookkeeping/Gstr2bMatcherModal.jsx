import React, { useState, useMemo } from 'react';
import { 
    FileSpreadsheet, Upload, CheckCircle2, AlertTriangle, 
    XCircle, HelpCircle, Download, ArrowRight, RefreshCw, X, ShieldAlert, FileText, Check, Plus
} from 'lucide-react';

const Gstr2bMatcherModal = ({ isOpen, onClose, clientPurchases = [], clientName = 'Client', onImportMissingBill }) => {
    if (!isOpen) return null;

    const [uploadedData, setUploadedData] = useState(null);
    const [fileName, setFileName] = useState('');
    const [activeFilter, setActiveFilter] = useState('ALL'); // ALL, MATCHED, MISMATCHED, MISSING_IN_BOOKS, MISSING_IN_2B
    const [searchTerm, setSearchTerm] = useState('');

    // Sample GSTR-2B generator for quick demonstration/testing
    const loadSample2B = () => {
        const sampleB2b = [
            {
                ctin: "37AABCT1332L1Z2",
                cname: "Sri Sai Enterprises",
                inv: [
                    {
                        inum: clientPurchases[0]?.docNumber || "VEND-2026-001",
                        idt: clientPurchases[0]?.docDate ? new Date(clientPurchases[0].docDate).toISOString().slice(0, 10) : "2026-04-12",
                        val: clientPurchases[0]?.summary?.totalAmount || 59000,
                        pos: "37",
                        itcavl: "Y",
                        items: [
                            {
                                num: 1,
                                txval: clientPurchases[0]?.summary?.totalTaxableValue || 50000,
                                rt: 18,
                                camt: clientPurchases[0]?.summary?.totalCgst || 4500,
                                samt: clientPurchases[0]?.summary?.totalSgst || 4500,
                                iamt: 0
                            }
                        ]
                    }
                ]
            },
            {
                ctin: "29AAACB2212K1Z9",
                cname: "Infosys Cloud Solutions Ltd",
                inv: [
                    {
                        inum: "INF-BLR-8841",
                        idt: "2026-04-18",
                        val: 23600,
                        pos: "37",
                        itcavl: "Y",
                        items: [
                            {
                                num: 1,
                                txval: 20000,
                                rt: 18,
                                camt: 0,
                                samt: 0,
                                iamt: 3600
                            }
                        ]
                    }
                ]
            },
            {
                ctin: "37ABCDE5678F1Z5",
                cname: "Apex Office Supplies",
                inv: [
                    {
                        inum: "APX-9921",
                        idt: "2026-04-20",
                        val: 14160,
                        pos: "37",
                        itcavl: "Y",
                        items: [
                            {
                                num: 1,
                                txval: 12000,
                                rt: 18,
                                camt: 1080,
                                samt: 1080,
                                iamt: 0
                            }
                        ]
                    }
                ]
            }
        ];

        setFileName("GSTR2B_Sample_Portal_Return.json");
        setUploadedData({
            gstin: "37AADCV1234F1Z1",
            fp: "042026",
            data: { b2b: sampleB2b }
        });
    };

    // File Upload Handler
    const handleFileUpload = (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setFileName(file.name);
        const reader = new FileReader();
        reader.onload = (evt) => {
            try {
                const parsed = JSON.parse(evt.target.result);
                setUploadedData(parsed);
            } catch (err) {
                alert('Invalid JSON file. Please upload an official GSTR-2B JSON export from the GST portal.');
            }
        };
        reader.readAsText(file);
    };

    // Reconciliation Calculation Engine
    const reconciliationResults = useMemo(() => {
        if (!uploadedData) return { rows: [], stats: { total2b: 0, totalBooks: 0, matched: 0, mismatched: 0, missingInBooks: 0, missingIn2B: 0, itc2b: 0, itcBooks: 0, itcMatched: 0 } };

        // 1. Flatten GSTR-2B Invoices
        const b2bInvoices = [];
        const rawB2b = uploadedData?.data?.b2b || uploadedData?.b2b || [];

        rawB2b.forEach(supplier => {
            const ctin = (supplier.ctin || '').trim().toUpperCase();
            const cname = supplier.cname || supplier.tradeName || 'Vendor';
            (supplier.inv || []).forEach(inv => {
                let taxable = 0;
                let cgst = 0;
                let sgst = 0;
                let igst = 0;

                (inv.items || []).forEach(item => {
                    const it = item.itm_det || item;
                    taxable += Number(it.txval || 0);
                    cgst += Number(it.camt || 0);
                    sgst += Number(it.samt || 0);
                    igst += Number(it.iamt || 0);
                });

                const totalTax = cgst + sgst + igst;
                const invoiceTotal = Number(inv.val || (taxable + totalTax));

                b2bInvoices.push({
                    ctin,
                    supplierName: cname,
                    inum: (inv.inum || '').trim(),
                    idt: inv.idt,
                    taxable,
                    cgst,
                    sgst,
                    igst,
                    totalTax,
                    invoiceTotal,
                    itcavl: inv.itcavl || 'Y',
                    matched: false
                });
            });
        });

        // 2. Prepare client recorded purchases
        const booksList = (clientPurchases || []).map(p => {
            const partyGstin = (p.partyGstin || '').trim().toUpperCase();
            const docNumber = (p.docNumber || '').trim();
            const taxable = Number(p.summary?.totalTaxableValue || 0);
            const cgst = Number(p.summary?.totalCgst || 0);
            const sgst = Number(p.summary?.totalSgst || 0);
            const igst = Number(p.summary?.totalIgst || 0);
            const totalTax = cgst + sgst + igst;
            const invoiceTotal = Number(p.summary?.totalAmount || (taxable + totalTax));

            return {
                id: p._id,
                partyName: p.partyName,
                partyGstin,
                docNumber,
                docDate: p.docDate ? new Date(p.docDate).toISOString().slice(0, 10) : '',
                taxable,
                cgst,
                sgst,
                igst,
                totalTax,
                invoiceTotal,
                matched: false,
                rawDoc: p
            };
        });

        const rows = [];
        let matchedCount = 0;
        let mismatchedCount = 0;
        let itcMatchedAmt = 0;

        // 3. Match 2B items with Books
        b2bInvoices.forEach(inv2b => {
            // Match criteria: same GSTIN and invoice number (case-insensitive & stripped)
            const matchedBook = booksList.find(b => 
                !b.matched && 
                (b.docNumber.toLowerCase().replace(/[^a-z0-9]/g, '') === inv2b.inum.toLowerCase().replace(/[^a-z0-9]/g, '') ||
                 (b.partyGstin && b.partyGstin === inv2b.ctin))
            );

            if (matchedBook) {
                matchedBook.matched = true;
                inv2b.matched = true;

                const taxDiff = Math.abs(matchedBook.totalTax - inv2b.totalTax);
                const taxableDiff = Math.abs(matchedBook.taxable - inv2b.taxable);

                if (taxDiff <= 5 && taxableDiff <= 5) {
                    matchedCount++;
                    itcMatchedAmt += inv2b.totalTax;
                    rows.push({
                        status: 'MATCHED',
                        gstin: inv2b.ctin,
                        supplierName: inv2b.supplierName || matchedBook.partyName,
                        invoiceNo: inv2b.inum,
                        invoiceDate: inv2b.idt || matchedBook.docDate,
                        taxable2b: inv2b.taxable,
                        taxableBooks: matchedBook.taxable,
                        tax2b: inv2b.totalTax,
                        taxBooks: matchedBook.totalTax,
                        total2b: inv2b.invoiceTotal,
                        totalBooks: matchedBook.invoiceTotal,
                        bookItem: matchedBook
                    });
                } else {
                    mismatchedCount++;
                    rows.push({
                        status: 'MISMATCHED',
                        gstin: inv2b.ctin,
                        supplierName: inv2b.supplierName || matchedBook.partyName,
                        invoiceNo: inv2b.inum,
                        invoiceDate: inv2b.idt || matchedBook.docDate,
                        taxable2b: inv2b.taxable,
                        taxableBooks: matchedBook.taxable,
                        tax2b: inv2b.totalTax,
                        taxBooks: matchedBook.totalTax,
                        total2b: inv2b.invoiceTotal,
                        totalBooks: matchedBook.invoiceTotal,
                        discrepancyNote: `Tax diff: ₹${taxDiff.toFixed(2)}, Taxable diff: ₹${taxableDiff.toFixed(2)}`,
                        bookItem: matchedBook
                    });
                }
            } else {
                // In 2B, but missing in books!
                rows.push({
                    status: 'MISSING_IN_BOOKS',
                    gstin: inv2b.ctin,
                    supplierName: inv2b.supplierName,
                    invoiceNo: inv2b.inum,
                    invoiceDate: inv2b.idt,
                    taxable2b: inv2b.taxable,
                    taxableBooks: 0,
                    tax2b: inv2b.totalTax,
                    taxBooks: 0,
                    total2b: inv2b.invoiceTotal,
                    totalBooks: 0,
                    raw2b: inv2b
                });
            }
        });

        // 4. Find purchases in Books that never appeared in GSTR-2B
        booksList.forEach(book => {
            if (!book.matched) {
                rows.push({
                    status: 'MISSING_IN_2B',
                    gstin: book.partyGstin || 'URP / Not Set',
                    supplierName: book.partyName,
                    invoiceNo: book.docNumber,
                    invoiceDate: book.docDate,
                    taxable2b: 0,
                    taxableBooks: book.taxable,
                    tax2b: 0,
                    taxBooks: book.totalTax,
                    total2b: 0,
                    totalBooks: book.invoiceTotal,
                    bookItem: book
                });
            }
        });

        // Compute summary metrics
        const totalItc2b = b2bInvoices.reduce((sum, i) => sum + i.totalTax, 0);
        const totalItcBooks = booksList.reduce((sum, b) => sum + b.totalTax, 0);
        const missingInBooksCount = rows.filter(r => r.status === 'MISSING_IN_BOOKS').length;
        const missingIn2bCount = rows.filter(r => r.status === 'MISSING_IN_2B').length;

        return {
            rows,
            stats: {
                total2b: b2bInvoices.length,
                totalBooks: booksList.length,
                matched: matchedCount,
                mismatched: mismatchedCount,
                missingInBooks: missingInBooksCount,
                missingIn2B: missingIn2bCount,
                itc2b: totalItc2b,
                itcBooks: totalItcBooks,
                itcMatched: itcMatchedAmt
            }
        };
    }, [uploadedData, clientPurchases]);

    const filteredRows = useMemo(() => {
        return reconciliationResults.rows.filter(r => {
            const matchesFilter = 
                activeFilter === 'ALL' ||
                r.status === activeFilter;
            
            const matchesSearch = 
                searchTerm === '' ||
                r.supplierName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                r.invoiceNo.toLowerCase().includes(searchTerm.toLowerCase()) ||
                r.gstin.toLowerCase().includes(searchTerm.toLowerCase());

            return matchesFilter && matchesSearch;
        });
    }, [reconciliationResults.rows, activeFilter, searchTerm]);

    return (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto">
            <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-6xl max-h-[92vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                {/* Modal Header */}
                <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-gradient-to-r from-slate-900 to-indigo-950 text-white">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-2xl bg-indigo-500/20 border border-indigo-400/30 flex items-center justify-center text-indigo-300">
                            <FileSpreadsheet size={20} />
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h3 className="text-lg font-black text-white">GSTR-2B vs Purchases ITC Reconciliation Desk</h3>
                                <span className="text-[10px] font-bold bg-indigo-500/30 text-indigo-200 px-2 py-0.5 rounded-full border border-indigo-400/20">
                                    FY 2026-27
                                </span>
                            </div>
                            <p className="text-xs text-slate-300">
                                Client: <strong className="text-white font-bold">{clientName}</strong> • Match inward supplier invoices to claim 100% legitimate GST Input Tax Credit.
                            </p>
                        </div>
                    </div>

                    <button 
                        onClick={onClose}
                        className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 text-white flex items-center justify-center transition"
                    >
                        <X size={18} />
                    </button>
                </div>

                {/* Main Content Area */}
                <div className="p-6 overflow-y-auto flex-1 space-y-6">
                    {/* Top Upload Banner */}
                    {!uploadedData ? (
                        <div className="border-2 border-dashed border-slate-200 rounded-3xl p-8 text-center bg-slate-50/50 hover:bg-slate-50 transition space-y-4">
                            <div className="w-16 h-16 rounded-3xl bg-indigo-50 text-indigo-600 flex items-center justify-center mx-auto shadow-sm">
                                <Upload size={28} />
                            </div>
                            <div>
                                <h4 className="font-black text-slate-800 text-base">Upload Official GSTR-2B Return JSON</h4>
                                <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                                    Download the auto-drafted GSTR-2B JSON file from <a href="https://services.gst.gov.in" target="_blank" rel="noreferrer" className="text-indigo-600 underline font-bold">gst.gov.in</a> and upload it here.
                                </p>
                            </div>

                            <div className="flex items-center justify-center gap-3 pt-2">
                                <label className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider cursor-pointer transition shadow-md shadow-indigo-100 flex items-center gap-2">
                                    <Upload size={15} /> Select 2B JSON File
                                    <input 
                                        type="file" 
                                        accept=".json,application/json" 
                                        onChange={handleFileUpload}
                                        className="hidden" 
                                    />
                                </label>

                                <span className="text-xs text-slate-400 font-bold">OR</span>

                                <button
                                    onClick={loadSample2B}
                                    className="bg-slate-900 hover:bg-slate-800 text-white px-5 py-2.5 rounded-2xl font-bold text-xs uppercase tracking-wider transition flex items-center gap-2 shadow-sm"
                                >
                                    ✨ Load Sample GSTR-2B Data
                                </button>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-indigo-50/60 border border-indigo-100 rounded-2xl p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                            <div className="flex items-center gap-3">
                                <div className="w-9 h-9 rounded-xl bg-indigo-600 text-white flex items-center justify-center font-bold">
                                    ✓
                                </div>
                                <div>
                                    <h5 className="font-black text-indigo-950 text-xs flex items-center gap-2">
                                        Active Statement: {fileName}
                                        <span className="text-[10px] font-bold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded">Parsed</span>
                                    </h5>
                                    <p className="text-[11px] text-indigo-700">
                                        GSTIN: {uploadedData.gstin || 'Client GSTIN'} • Period: {uploadedData.fp || 'Current Month'} • {reconciliationResults.stats.total2b} B2B Invoices Found
                                    </p>
                                </div>
                            </div>

                            <div className="flex items-center gap-2">
                                <label className="bg-white hover:bg-slate-50 text-indigo-600 border border-indigo-200 px-3 py-1.5 rounded-xl font-bold text-xs cursor-pointer transition shadow-sm flex items-center gap-1.5">
                                    <RefreshCw size={13} /> Re-upload
                                    <input type="file" accept=".json,application/json" onChange={handleFileUpload} className="hidden" />
                                </label>
                            </div>
                        </div>
                    )}

                    {/* Stats Dashboard */}
                    {uploadedData && (
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-1">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Total GSTR-2B ITC</span>
                                <div className="text-base sm:text-lg font-black font-mono text-indigo-900">
                                    ₹{reconciliationResults.stats.itc2b.toLocaleString('en-IN')}
                                </div>
                                <p className="text-[10px] text-slate-500">{reconciliationResults.stats.total2b} Supplier Invoices</p>
                            </div>

                            <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-1">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Total Books ITC</span>
                                <div className="text-base sm:text-lg font-black font-mono text-slate-800">
                                    ₹{reconciliationResults.stats.itcBooks.toLocaleString('en-IN')}
                                </div>
                                <p className="text-[10px] text-slate-500">{reconciliationResults.stats.totalBooks} Purchase Bills</p>
                            </div>

                            <div className="bg-emerald-50 p-4 rounded-2xl border border-emerald-200 space-y-1">
                                <span className="text-[10px] font-bold text-emerald-800 uppercase tracking-wider">Matched & Eligible ITC</span>
                                <div className="text-base sm:text-lg font-black font-mono text-emerald-700">
                                    ₹{reconciliationResults.stats.itcMatched.toLocaleString('en-IN')}
                                </div>
                                <p className="text-[10px] text-emerald-600 font-bold">{reconciliationResults.stats.matched} Invoices 100% Matched</p>
                            </div>

                            <div className="bg-rose-50 p-4 rounded-2xl border border-rose-200 space-y-1">
                                <span className="text-[10px] font-bold text-rose-800 uppercase tracking-wider">Discrepancies / Unfiled</span>
                                <div className="text-base sm:text-lg font-black font-mono text-rose-700">
                                    {reconciliationResults.stats.mismatched + reconciliationResults.stats.missingIn2B}
                                </div>
                                <p className="text-[10px] text-rose-600 font-bold">Action Required</p>
                            </div>
                        </div>
                    )}

                    {/* Filter Tabs & Search */}
                    {uploadedData && (
                        <div className="space-y-3">
                            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                                <div className="flex items-center gap-1.5 flex-wrap bg-slate-100 p-1.5 rounded-2xl">
                                    <button
                                        onClick={() => setActiveFilter('ALL')}
                                        className={`px-3 py-1.5 rounded-xl font-bold text-xs transition ${activeFilter === 'ALL' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}
                                    >
                                        All Invoices ({reconciliationResults.rows.length})
                                    </button>
                                    <button
                                        onClick={() => setActiveFilter('MATCHED')}
                                        className={`px-3 py-1.5 rounded-xl font-bold text-xs transition flex items-center gap-1.5 ${activeFilter === 'MATCHED' ? 'bg-emerald-600 text-white shadow-sm' : 'text-emerald-700 hover:bg-emerald-50'}`}
                                    >
                                        <CheckCircle2 size={13} /> Matched ({reconciliationResults.stats.matched})
                                    </button>
                                    <button
                                        onClick={() => setActiveFilter('MISMATCHED')}
                                        className={`px-3 py-1.5 rounded-xl font-bold text-xs transition flex items-center gap-1.5 ${activeFilter === 'MISMATCHED' ? 'bg-amber-600 text-white shadow-sm' : 'text-amber-700 hover:bg-amber-50'}`}
                                    >
                                        <AlertTriangle size={13} /> Tax Mismatch ({reconciliationResults.stats.mismatched})
                                    </button>
                                    <button
                                        onClick={() => setActiveFilter('MISSING_IN_BOOKS')}
                                        className={`px-3 py-1.5 rounded-xl font-bold text-xs transition flex items-center gap-1.5 ${activeFilter === 'MISSING_IN_BOOKS' ? 'bg-indigo-600 text-white shadow-sm' : 'text-indigo-700 hover:bg-indigo-50'}`}
                                    >
                                        <Plus size={13} /> Missing in Books ({reconciliationResults.stats.missingInBooks})
                                    </button>
                                    <button
                                        onClick={() => setActiveFilter('MISSING_IN_2B')}
                                        className={`px-3 py-1.5 rounded-xl font-bold text-xs transition flex items-center gap-1.5 ${activeFilter === 'MISSING_IN_2B' ? 'bg-rose-600 text-white shadow-sm' : 'text-rose-700 hover:bg-rose-50'}`}
                                    >
                                        <XCircle size={13} /> Missing in 2B ({reconciliationResults.stats.missingIn2B})
                                    </button>
                                </div>

                                <input 
                                    type="text"
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    placeholder="Search vendor, GSTIN, invoice #..."
                                    className="bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-1.5 text-xs font-medium w-full md:w-64 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>

                            {/* Comparison Table */}
                            <div className="border border-slate-200 rounded-2xl overflow-hidden shadow-sm">
                                <div className="overflow-x-auto">
                                    <table className="w-full text-left border-collapse text-xs">
                                        <thead>
                                            <tr className="bg-slate-50 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-200">
                                                <th className="px-4 py-3">Status</th>
                                                <th className="px-4 py-3">Supplier GSTIN & Name</th>
                                                <th className="px-4 py-3">Invoice # & Date</th>
                                                <th className="px-4 py-3 text-right">Taxable (2B vs Books)</th>
                                                <th className="px-4 py-3 text-right">Tax / ITC (2B vs Books)</th>
                                                <th className="px-4 py-3 text-center">Action</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-100">
                                            {filteredRows.length === 0 ? (
                                                <tr>
                                                    <td colSpan={6} className="text-center py-12 text-slate-400">
                                                        No reconciliation entries match the selected filter.
                                                    </td>
                                                </tr>
                                            ) : (
                                                filteredRows.map((row, idx) => (
                                                    <tr key={idx} className="hover:bg-slate-50/70 transition">
                                                        <td className="px-4 py-3.5">
                                                            {row.status === 'MATCHED' && (
                                                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider bg-emerald-50 text-emerald-700 border border-emerald-200">
                                                                    <CheckCircle2 size={12} /> Matched
                                                                </span>
                                                            )}
                                                            {row.status === 'MISMATCHED' && (
                                                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider bg-amber-50 text-amber-700 border border-amber-200">
                                                                    <AlertTriangle size={12} /> Tax Diff
                                                                </span>
                                                            )}
                                                            {row.status === 'MISSING_IN_BOOKS' && (
                                                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200">
                                                                    <Plus size={12} /> Unrecorded
                                                                </span>
                                                            )}
                                                            {row.status === 'MISSING_IN_2B' && (
                                                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider bg-rose-50 text-rose-700 border border-rose-200">
                                                                    <XCircle size={12} /> Not in 2B
                                                                </span>
                                                            )}
                                                        </td>

                                                        <td className="px-4 py-3.5">
                                                            <div className="font-bold text-slate-900">{row.supplierName}</div>
                                                            <div className="font-mono text-[10px] text-slate-400 font-bold">{row.gstin}</div>
                                                        </td>

                                                        <td className="px-4 py-3.5">
                                                            <div className="font-mono font-bold text-slate-800">{row.invoiceNo}</div>
                                                            <div className="text-[10px] text-slate-400">{row.invoiceDate}</div>
                                                        </td>

                                                        <td className="px-4 py-3.5 text-right font-mono">
                                                            <div className="text-slate-900 font-bold">2B: ₹{row.taxable2b.toLocaleString('en-IN')}</div>
                                                            <div className="text-slate-400 text-[10px]">Books: ₹{row.taxableBooks.toLocaleString('en-IN')}</div>
                                                        </td>

                                                        <td className="px-4 py-3.5 text-right font-mono">
                                                            <div className={`font-black ${row.status === 'MATCHED' ? 'text-emerald-600' : row.status === 'MISSING_IN_2B' ? 'text-rose-600' : 'text-slate-900'}`}>
                                                                2B: ₹{row.tax2b.toLocaleString('en-IN')}
                                                            </div>
                                                            <div className="text-slate-400 text-[10px]">Books: ₹{row.taxBooks.toLocaleString('en-IN')}</div>
                                                        </td>

                                                        <td className="px-4 py-3.5 text-center">
                                                            {row.status === 'MISSING_IN_BOOKS' && onImportMissingBill && (
                                                                <button
                                                                    onClick={() => onImportMissingBill(row.raw2b)}
                                                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1 rounded-xl text-[10px] font-bold transition shadow-sm flex items-center gap-1 mx-auto"
                                                                >
                                                                    <Plus size={11} /> Import as Bill
                                                                </button>
                                                            )}
                                                            {row.status === 'MATCHED' && (
                                                                <span className="text-[10px] font-bold text-emerald-600 flex items-center justify-center gap-1">
                                                                    <Check size={12} /> Claim In 3B
                                                                </span>
                                                            )}
                                                            {row.status === 'MISSING_IN_2B' && (
                                                                <span className="text-[10px] font-bold text-rose-500">
                                                                    Follow up vendor
                                                                </span>
                                                            )}
                                                            {row.status === 'MISMATCHED' && (
                                                                <span className="text-[10px] font-bold text-amber-600">
                                                                    Review Entry
                                                                </span>
                                                            )}
                                                        </td>
                                                    </tr>
                                                ))
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Modal Footer */}
                <div className="p-4 border-t border-slate-100 bg-slate-50 flex justify-between items-center text-xs">
                    <span className="text-slate-500 font-medium">
                        Rule 36(4) Compliant: ITC claim is restricted to invoices reflected in GSTR-2B.
                    </span>
                    <button
                        onClick={onClose}
                        className="bg-slate-900 hover:bg-slate-800 text-white px-5 py-2 rounded-xl font-bold transition shadow-sm"
                    >
                        Done / Close Desk
                    </button>
                </div>
            </div>
        </div>
    );
};

export default Gstr2bMatcherModal;
