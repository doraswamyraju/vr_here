# VR HERE Cross-Platform Feature Parity & Implementation Roadmap

> **Standard Principle**: Single Source of Truth across Database, APIs, Web Portal, Android, and iOS. Identical calculation methods, standardized models, and zero assumptions.

---

## 📋 Executive Overview & Implementation Scope

| Item | Feature | Web Admin / Customer | Android (`VRHereBMS`) | iOS (`VRHereIOS`) |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Phone Contacts Import / Export | ❌ Not needed (Mobile only) | ✅ **Completed** | 🔜 To be implemented |
| **2** | Standardized GST & Proforma Invoice PDF | 🔄 **To implement in Web** | ✅ **Completed** | 🔜 To be implemented |
| **3** | Floating Support Action Hub | ✅ Already present | ✅ **Completed** | 🔜 To be implemented |
| **4** | Dynamic Blogs & Regulatory Insights CMS | 🔄 **To implement in Admin** | ✅ UI Ready (Needs API sync) | 🔜 To be implemented |
| **5** | Dynamic Offers & Schemes CMS (with Images) | 🔄 **To implement in Admin** | ✅ UI Ready (Needs API sync) | 🔜 To be implemented |
| **6** | Notification Center & Deep-Linking | ✅ Already present | ✅ **Completed** | 🔜 To be implemented |
| **7** | Edge-to-Edge / System Inset Protection | ❌ Not needed (Web responsive) | ✅ **Completed** | 🔜 SafeArea / Inset Parity |
| **8** | Mobile Gestures & Swipe Back | ❌ Not needed (Browser history) | ✅ **Completed** | 🔜 InteractivePopGesture |
| **9** | Google Authentication | ✅ Already working | ✅ Signed & Integrated | 🔜 Google Sign-In SDK |

---

## 🎯 Phase 1: Web Backend & Admin Panel Implementation

### 1.1 Backend Models & Database Schemas (`MongoDB / Mongoose`)

#### A. Blog / Regulatory Insight Schema (`backend/models/Blog.js`)
```javascript
import mongoose from 'mongoose';

const blogSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
    summary: { type: String, required: true },
    category: { 
        type: String, 
        required: true, 
        enum: ['Corporate & Legal', 'GST & Direct Taxes', 'Startups & Funding', 'IPR & Legal', 'Accounting & Payroll', 'Compliance Alert']
    },
    categoryColor: { type: String, default: '#3B82F6' },
    readTime: { type: String, default: '4 min read' },
    coverImageUrl: { type: String, default: '' },
    keyTakeaways: [{ type: String }],
    fullArticle: { type: String, required: true },
    isPublished: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    author: { type: String, default: 'VR HERE Editorial Board' },
    publishedAt: { type: Date, default: Date.now }
}, { timestamps: true });

export default mongoose.model('Blog', blogSchema);
```

#### B. Featured Offer / Scheme Schema (`backend/models/Offer.js`)
```javascript
import mongoose from 'mongoose';

const offerSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    subtitle: { type: String, required: true },
    badgeTag: { type: String, default: 'LIMITED TIME' },
    badgeColor: { type: String, default: '#DC2626' },
    bannerImageUrl: { type: String, default: '' },
    targetServiceKey: { type: String, default: '' },
    targetUrl: { type: String, default: '' },
    discountAmount: { type: Number, default: 0 },
    originalPrice: { type: Number, default: 0 },
    discountedPrice: { type: Number, default: 0 },
    eligibilityText: { type: String, default: 'Tap to view eligibility & apply' },
    ctaText: { type: String, default: 'Register Today →' },
    isActive: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    validUntil: { type: Date, default: null }
}, { timestamps: true });

export default mongoose.model('Offer', offerSchema);
```

---

### 1.2 REST API Endpoints (`backend/routes/`)

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/blogs` | Public | Fetch all published blog articles & regulatory insights |
| `GET` | `/api/blogs/:slug` | Public | Fetch single article detail by slug |
| `POST` | `/api/admin/blogs` | Admin Only | Create new blog post with takeaways & cover image |
| `PUT` | `/api/admin/blogs/:id` | Admin Only | Update existing blog post |
| `DELETE` | `/api/admin/blogs/:id` | Admin Only | Delete blog post |
| `GET` | `/api/offers` | Public | Fetch active promotional offers & banners |
| `POST` | `/api/admin/offers` | Admin Only | Create promotional offer with image & pricing |
| `PUT` | `/api/admin/offers/:id` | Admin Only | Update existing offer |
| `DELETE` | `/api/admin/offers/:id` | Admin Only | Delete / deactivate offer |

---

### 1.3 Web Admin Panel Modules (`frontend/components/admin/`)

1. **Blog & Insights Studio (`AdminBlogsView.jsx`)**:
   - Table view with search, filter by category, and active/inactive status toggle.
   - Rich form modal:
     - Title, Slug, Category dropdown, Estimated Read Time.
     - Cover image upload (or direct URL input).
     - Dynamic **Key Takeaways** list builder (add/remove bullet points).
     - Full article markdown / formatted text editor.
     - Live preview drawer matching both web customer dashboard and mobile modal.

2. **Promotional Offers & Schemes Studio (`AdminOffersView.jsx`)**:
   - Visual card grid of active promotional banners.
   - Modal form:
     - Offer Title, Subtitle, Badge Tag (e.g. `SAVE ₹4,999`, `ALL-IN-ONE PACK`).
     - Banner Image uploader (accommodates high-res image creatives).
     - Original Price vs. Discounted Price configurator.
     - Target Service Key link (maps directly to checkout & service detail).
     - Priority ordering and validity date picker.

3. **Standardized GST Tax Invoice Generator on Web**:
   - Port the exact, audited A4 Tax Invoice canvas/PDF generator from the Bookkeeping module so that clicking "Download Invoice" anywhere in the Web Customer Suite produces the standardized format with:
     - Seller: `VR HERE BUSINESS MANAGEMENT SOLUTIONS PRIVATE LIMITED`
     - Trade Name: `VR HERE`
     - GSTIN: `37AAHCR7654E1Z8`
     - Place of Supply: `37-Andhra Pradesh`
     - Sac Code `998311` with 18% GST calculation (9% CGST + 9% SGST).

---

## 📱 Phase 2: Android Dynamic Sync (`VRHereBMS`)

Once the backend APIs are live:
1. Update `CustomerDashboardViewModel.kt` to fetch:
   - `api.getOffers()` $\rightarrow$ feeds `CustomerHomeTab.kt` carousel dynamically.
   - `api.getBlogs()` $\rightarrow$ feeds `Regulatory Insights` list and reader modal dynamically.
2. Maintain offline cached fallback presets so the app remains rich and responsive even without network.

---

## 🍏 Phase 3: Complete iOS Replication (`VRHereIOS`)

> **Prerequisite**: Execution starts only after complete sign-off of Web and Android.

### Exact Features to Replicate on iOS:
1. **SwiftUI Modern Home Dashboard**:
   - 4-Card executive KPI grid (Active Orders, Action Needed, Digital Vault, Due Balance / Portfolio Volume).
   - Dynamic **Auto-Sliding Offers Carousel** connected to `/api/offers`.
   - Dynamic **Regulatory Insights Reader** connected to `/api/blogs`.
   - **Floating Support Hub** (LetsTrack, WhatsApp, Phone Helpline, Raise Ticket).
2. **Bookkeeping & AaaS Master Module**:
   - Executive Dashboard, Income/Expenses, Purchase Bills, Sales Invoices, Bank Statements, Reports.
   - **Contacts Integration**: iOS `CNContactPickerViewController` to import name/phone/email from Apple Contacts, and `CNContact` export to save parties into iOS Address Book.
3. **Standardized PDF Invoice Generator**:
   - `UIGraphicsPDFRenderer` / SwiftUI PDFKit implementation replicating the exact A4 GST format with native iOS Share Sheet (`UIActivityViewController`).
4. **Interactive Support Chat**:
   - Native Socket.io client (`Socket.IO-Client-Swift`) connecting to `https://livechat.vrhere.in/visitor` with tenant key `lt_6a9347d5410be8335e42db43949caf95`.
5. **Google Sign-In & Authentication**:
   - GoogleSignIn iOS SDK (`GoogleSignIn.framework`) with `GIDSignIn` matching the OAuth Web Client ID.

---

## 🛡️ Consistency & Calculation Rules
1. **DUE BALANCE Formula** (Identical across Web, Android, iOS):
   $$\text{Balance Due} = \max\left(0, \text{Order Price} - \sum \text{Verified Completed Payments for Order}\right)$$
2. **Seller Entity Info**:
   - Legal Entity: `VR HERE BUSINESS MANAGEMENT SOLUTIONS PRIVATE LIMITED`
   - Trade Name: `VR HERE`
   - Address: `#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati, Andhra Pradesh - 517501`
   - Phone: `+91 80085 30606` | Email: `support@vrhere.in`
3. **No Assumptions**:
   - Every status calculation, due calculation, and requirement verification must strictly query the live database collections without hardcoded state bypasses.
