import SwiftUI
import Combine

// Status Badge matching Android StatusBadge 1:1
struct StatusBadge: View {
    let status: String
    
    var colors: (bg: Color, text: Color, border: Color) {
        switch status.lowercased() {
        case "processing at portal", "in progress":
            return (Color(red: 239/255, green: 246/255, blue: 255/255), Color(red: 29/255, green: 78/255, blue: 216/255), Color(red: 191/255, green: 219/255, blue: 254/255))
        case "waiting for clarification", "in review":
            return (Color(red: 250/255, green: 245/255, blue: 255/255), Color(red: 126/255, green: 34/255, blue: 206/255), Color(red: 233/255, green: 213/255, blue: 255/255))
        case "completed", "approved":
            return (Color(red: 236/255, green: 253/255, blue: 245/255), Color(red: 4/255, green: 120/255, blue: 87/255), Color(red: 167/255, green: 243/255, blue: 208/255))
        case "pending documents", "documents required":
            return (Color(red: 255/255, green: 251/255, blue: 235/255), Color(red: 180/255, green: 83/255, blue: 9/255), Color(red: 253/255, green: 230/255, blue: 138/255))
        case "documents verified":
            return (Color(red: 236/255, green: 253/255, blue: 245/255), Color(red: 5/255, green: 150/255, blue: 105/255), Color(red: 167/255, green: 243/255, blue: 208/255))
        default:
            return (Color(red: 241/255, green: 245/255, blue: 249/255), Color(red: 51/255, green: 65/255, blue: 85/255), Color(red: 226/255, green: 232/255, blue: 240/255))
        }
    }
    
    var body: some View {
        Text(status.uppercased())
            .font(.system(size: 9, weight: .black))
            .foregroundColor(colors.text)
            .tracking(0.5)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(colors.bg)
            .cornerRadius(20)
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .stroke(colors.border, lineWidth: 1)
            )
    }
}

// Quick Service Item Model
struct QuickServiceItem: Identifiable {
    let id: Int
    let name: String
    let tag: String
    let icon: String
    let iconBg: Color
    let iconTint: Color
    let targetTab: String
    let url: String?
}

// Promo Offer Item Model
struct PromoOfferItem: Identifiable {
    let id: String
    let tag: String
    let title: String
    let description: String
    let badge: String
    let bgColors: [Color]
    let accentColor: Color
    let icon: String
    let ctaText: String
    let liveServiceName: String?
    let liveServiceUrl: String?
    let targetTab: String
    let bannerImageUrl: String?
    let discountedPrice: Double
    let originalPrice: Double
}

// Blog Post Item Model
struct BlogPostItem: Identifiable {
    let id: String
    let title: String
    let summary: String
    let category: String
    let categoryColor: Color
    let readTime: String
    let publishDate: String
    let icon: String
    let keyTakeaways: [String]
    let fullArticle: String
    let coverImageUrl: String?
}

struct CustomerHomeTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let userName: String
    @Binding var searchQuery: String
    let onSelectTab: (String) -> Void
    let onOpenProject: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    let onLogout: () -> Void
    
    @State private var showSuggestions = false
    @State private var selectedBlogPost: BlogPostItem? = nil
    @State private var currentPromoIndex = 0
    @State private var timerSubscription: AnyCancellable? = nil
    
    @Environment(\.openURL) private var openURL
    
    // Status progress helper matching Android getStatusProgress
    private func getStatusProgress(_ status: String) -> Int {
        switch status.lowercased() {
        case "order placed", "pending": return 15
        case "pending documents", "documents required": return 25
        case "documents verified": return 40
        case "in progress", "processing at portal": return 65
        case "waiting for clarification", "in review": return 80
        case "completed", "approved": return 100
        default: return 30
        }
    }
    
    private var activeOrders: [OrderResponse] {
        viewModel.orders.filter { $0.status.lowercased() != "completed" }
    }
    
    private var completedOrders: [OrderResponse] {
        viewModel.orders.filter { $0.status.lowercased() == "completed" }
    }
    
    private var pendingActions: [OrderResponse] {
        viewModel.orders.filter { order in
            let s = order.status.lowercased()
            if s == "completed" || s == "documents verified" || s == "processing at portal" {
                return false
            }
            if s == "waiting for clarification" { return true }
            if s == "pending documents" || s == "documents required" {
                if !order.customerRequirements.isEmpty {
                    return order.customerRequirements.contains { req in
                        !req.isClientCompleted && req.uploadedDocumentUrl.isEmpty && req.documentUrl.isEmpty && req.clientValue.isEmpty && req.status.lowercased() != "received" && req.status.lowercased() != "verified"
                    }
                }
                return false
            }
            return false
        }
    }
    
    private var unpaidOrders: [OrderResponse] {
        viewModel.orders.filter { order in
            if order.status.lowercased() == "completed" { return false }
            let orderPrice = order.price
            let orderPayments = viewModel.payments.filter { p in
                p.order?.id == order.id || (!p.paymentId.isEmpty && p.paymentId == order.paymentId)
            }
            let totalPaid = orderPayments.filter {
                let ps = $0.status.lowercased()
                return ps == "completed" || ps == "paid"
            }.reduce(0.0) { $0 + $1.amount }
            
            let balanceDue = max(0.0, orderPrice - totalPaid)
            let pStatus = (order.paymentStatus ?? "").lowercased()
            let isExplicitUnpaid = pStatus == "pending" || pStatus == "partial" || pStatus == "unpaid"
            return balanceDue > 0 || (orderPrice > 0 && isExplicitUnpaid)
        }
    }
    
    private var totalOutstanding: Double {
        unpaidOrders.reduce(0.0) { sum, order in
            let orderPayments = viewModel.payments.filter { p in
                p.order?.id == order.id || (!p.paymentId.isEmpty && p.paymentId == order.paymentId)
            }
            let totalPaid = orderPayments.filter {
                let ps = $0.status.lowercased()
                return ps == "completed" || ps == "paid"
            }.reduce(0.0) { $0 + $1.amount }
            let balance = max(0.0, order.price - totalPaid)
            return sum + (balance > 0 ? balance : order.price)
        }
    }
    
    private var totalVolume: Double {
        viewModel.orders.reduce(0.0) { $0 + $1.price }
    }
    
    private let searchSuggestions = [
        "Private Limited Company Registration",
        "Limited Liability Partnership (LLP)",
        "GST Registration",
        "GST Return Filing",
        "Income Tax Return",
        "MSME / Udyam Registration",
        "Trademark Registration",
        "FSSAI Food License",
        "ISO Certification",
        "Import Export Code (IEC)",
        "Company Annual Compliances",
        "Startup India DPIIT Registration"
    ]
    
    private var filteredSuggestions: [String] {
        if searchQuery.trimmingCharacters(in: .whitespaces).isEmpty { return [] }
        return searchSuggestions.filter { $0.localizedCaseInsensitiveContains(searchQuery) }
    }
    
    private let topServices: [QuickServiceItem] = [
        QuickServiceItem(id: 1, name: "Pvt Ltd Setup", tag: "MCA Approval", icon: "building.2.fill", iconBg: Color(red: 254/255, green: 242/255, blue: 242/255), iconTint: Color.primaryRed, targetTab: "Services", url: "https://vrhere.in/pvt-ltd-registration"),
        QuickServiceItem(id: 2, name: "GST Filing", tag: "Monthly / QRMP", icon: "checkmark.seal.fill", iconBg: Color(red: 236/255, green: 253/255, blue: 245/255), iconTint: Color(red: 16/255, green: 185/255, blue: 129/255), targetTab: "Services", url: "https://vrhere.in/gst-registration"),
        QuickServiceItem(id: 3, name: "Income Tax", tag: "ITR 1-7 Assessment", icon: "desktopcomputer", iconBg: Color(red: 239/255, green: 246/255, blue: 255/255), iconTint: Color(red: 37/255, green: 99/255, blue: 235/255), targetTab: "Services", url: "https://vrhere.in/income-tax-return"),
        QuickServiceItem(id: 4, name: "Partnership", tag: "Firm & Deed", icon: "person.2.fill", iconBg: Color(red: 255/255, green: 251/255, blue: 235/255), iconTint: Color(red: 245/255, green: 158/255, blue: 11/255), targetTab: "Services", url: "https://vrhere.in/partnership-firm"),
        QuickServiceItem(id: 5, name: "ISO Standards", tag: "9001 / 27001", icon: "shield.checkmark.fill", iconBg: Color(red: 250/255, green: 245/255, blue: 255/255), iconTint: Color(red: 147/255, green: 51/255, blue: 234/255), targetTab: "Services", url: nil),
        QuickServiceItem(id: 6, name: "Audit Support", tag: "Statutory & Tax", icon: "doc.text.badge.checkmark", iconBg: Color(red: 255/255, green: 241/255, blue: 242/255), iconTint: Color(red: 225/255, green: 29/255, blue: 72/255), targetTab: "Support", url: nil),
        QuickServiceItem(id: 7, name: "MSME Loans", tag: "Bank DPR & CMA", icon: "indianrupeesign", iconBg: Color(red: 236/255, green: 253/255, blue: 245/255), iconTint: Color(red: 5/255, green: 150/255, blue: 105/255), targetTab: "Services", url: nil),
        QuickServiceItem(id: 8, name: "ROC CCFS-2026", tag: "Penalty Relief", icon: "sparkles", iconBg: Color(red: 255/255, green: 247/255, blue: 237/255), iconTint: Color(red: 234/255, green: 88/255, blue: 12/255), targetTab: "Services", url: "https://vrhere.in/compliance-scheme-2026")
    ]
    
    private var promoOffers: [PromoOfferItem] {
        let dynamic = viewModel.offers.filter { $0.isActive == true }
        if !dynamic.isEmpty {
            return dynamic.map { o in
                let accent = o.badgeColor != nil && !o.badgeColor!.isEmpty ? Color(hex: o.badgeColor!) : Color.primaryRed
                return PromoOfferItem(
                    id: o.id,
                    tag: o.badgeTag ?? "FEATURED",
                    title: o.title,
                    description: o.subtitle,
                    badge: (o.discountAmount ?? 0) > 0 ? "SAVE ₹\(Int(o.discountAmount!))" : "FEATURED",
                    bgColors: [Color.darkSlate, accent.opacity(0.5)],
                    accentColor: accent,
                    icon: "tag.fill",
                    ctaText: o.ctaText ?? "Claim Offer →",
                    liveServiceName: o.title,
                    liveServiceUrl: o.targetUrl,
                    targetTab: "Services",
                    bannerImageUrl: o.bannerImageUrl,
                    discountedPrice: o.discountedPrice ?? 0,
                    originalPrice: o.originalPrice ?? 0
                )
            }
        }
        
        return [
            PromoOfferItem(
                id: "offer-ccfs-2026",
                tag: "GOVERNMENT AMNESTY",
                title: "ROC CCFS-2026 Amnesty Scheme",
                description: "100% Late Filing Penalty Waiver for pending MCA returns. Clear years of default with zero additional fees.",
                badge: "LIMITED PERIOD",
                bgColors: [Color.darkSlate, Color(red: 131/255, green: 24/255, blue: 67/255)],
                accentColor: Color(red: 244/255, green: 63/255, blue: 94/255),
                icon: "sparkles",
                ctaText: "Avail Scheme →",
                liveServiceName: "CCFS-2026 Scheme",
                liveServiceUrl: "https://vrhere.in/compliance-scheme-2026",
                targetTab: "Services",
                bannerImageUrl: "https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=800&auto=format&fit=crop&q=80",
                discountedPrice: 5000.0,
                originalPrice: 15000.0
            ),
            PromoOfferItem(
                id: "offer-startup-80iac",
                tag: "TAX HOLIDAY",
                title: "Startup India & 80-IAC 3-Year Exemption",
                description: "Get 100% Income Tax Exemption for 3 consecutive years with DPIIT Recognition & IMB Certification.",
                badge: "DPIIT APPROVED",
                bgColors: [Color.darkSlate, Color(red: 6/255, green: 95/255, blue: 70/255)],
                accentColor: Color(red: 16/255, green: 185/255, blue: 129/255),
                icon: "airplane.departure",
                ctaText: "Apply Now →",
                liveServiceName: "Startup India Registration",
                liveServiceUrl: "https://vrhere.in/startup-india",
                targetTab: "Services",
                bannerImageUrl: "https://images.unsplash.com/photo-1519389950473-47ba0277781c?w=800&auto=format&fit=crop&q=80",
                discountedPrice: 9999.0,
                originalPrice: 14999.0
            ),
            PromoOfferItem(
                id: "offer-pvt-ltd-pack",
                tag: "ALL-IN-ONE PACK",
                title: "Free GST + MSME with Pvt Ltd",
                description: "Complete incorporation with DIN, DSC, MOA, AOA, PAN, TAN, GSTIN & MSME Udyam registration included.",
                badge: "SAVE ₹4,999",
                bgColors: [Color.darkSlate, Color(red: 49/255, green: 46/255, blue: 129/255)],
                accentColor: Color(red: 99/255, green: 102/255, blue: 241/255),
                icon: "building.2.fill",
                ctaText: "Register Today →",
                liveServiceName: "Private Limited Registration",
                liveServiceUrl: "https://vrhere.in/pvt-ltd-registration",
                targetTab: "Services",
                bannerImageUrl: "https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=800&auto=format&fit=crop&q=80",
                discountedPrice: 7999.0,
                originalPrice: 12999.0
            ),
            PromoOfferItem(
                id: "offer-iso-fasttrack",
                tag: "FAST-TRACK DISPATCH",
                title: "Fast-Track ISO 9001 / 27001",
                description: "Globally recognized IAF/UAF accredited certification delivered in 3 working days for tender eligibility.",
                badge: "3-DAY DISPATCH",
                bgColors: [Color.darkSlate, Color(red: 120/255, green: 53/255, blue: 15/255)],
                accentColor: Color(red: 245/255, green: 158/255, blue: 11/255),
                icon: "shield.fill",
                ctaText: "Get Certified →",
                liveServiceName: "ISO Certification",
                liveServiceUrl: nil,
                targetTab: "Services",
                bannerImageUrl: "https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=800&auto=format&fit=crop&q=80",
                discountedPrice: 6999.0,
                originalPrice: 9999.0
            )
        ]
    }
    
    private var blogPosts: [BlogPostItem] {
        let dynamic = viewModel.blogs.filter { $0.isPublished == true }
        if !dynamic.isEmpty {
            return dynamic.map { b in
                let catColor = b.categoryColor != nil && !b.categoryColor!.isEmpty ? Color(hex: b.categoryColor!) : Color(red: 37/255, green: 99/255, blue: 235/255)
                return BlogPostItem(
                    id: b.id,
                    title: b.title,
                    summary: b.summary,
                    category: b.category,
                    categoryColor: catColor,
                    readTime: (b.readTime?.isEmpty ?? true) ? "4 min read" : b.readTime!,
                    publishDate: b.publishedAt != nil ? String(b.publishedAt!.prefix(10)) : "Mar 2026",
                    icon: "doc.text.fill",
                    keyTakeaways: b.keyTakeaways ?? [],
                    fullArticle: b.fullArticle.isEmpty ? b.summary : b.fullArticle,
                    coverImageUrl: b.coverImageUrl
                )
            }
        }
        
        return [
            BlogPostItem(
                id: "blog-mca-kyc-2026",
                title: "MCA Annual Returns & Director KYC: Mandatory Compliance Guide (FY 2025-26)",
                summary: "Complete roadmap on Form AOC-4, MGT-7, and DIR-3 KYC timelines to avoid director disqualification and ₹100/day penalties under the Companies Act.",
                category: "Corporate & Legal",
                categoryColor: Color(red: 37/255, green: 99/255, blue: 235/255),
                readTime: "4 min read",
                publishDate: "Mar 2026",
                icon: "building.2.fill",
                keyTakeaways: [
                    "DIR-3 KYC mandatory annually for all active DIN holders",
                    "AOC-4 (Financial Statements) due within 30 days of AGM",
                    "MGT-7 (Annual Return) due within 60 days of AGM",
                    "Late fee accumulates at ₹100 per day with no upper cap unless under amnesty"
                ],
                fullArticle: """
                Every registered Private Limited and Public Limited Company in India is legally mandated to maintain active compliance with the Ministry of Corporate Affairs (MCA).
                
                1. DIR-3 KYC Filing:
                Every individual holding a Director Identification Number (DIN) must complete Web KYC or e-Form DIR-3 KYC before the cutoff date. Failure to file leads to deactivation of DIN and a standard penalty of ₹5,000 per DIN.
                
                2. Form AOC-4 (Financial Statements):
                Must include the Audited Balance Sheet, Profit & Loss Statement, Auditor's Report, and Director's Report. It must be filed within 30 days from the date of the Annual General Meeting (AGM).
                
                3. Form MGT-7 / MGT-7A (Annual Return):
                Small companies can file MGT-7A, while other companies file MGT-7. This captures shareholding patterns, directorship changes, and board meetings held during the financial year.
                
                4. Impact of Non-Compliance:
                Non-filing triggers disqualification of directors under Section 164(2) for 5 years and potential striking off by the ROC under Section 248. VR Here's corporate legal team handles end-to-end preparation and MCA portal filing.
                """,
                coverImageUrl: "https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=800&auto=format&fit=crop&q=80"
            ),
            BlogPostItem(
                id: "blog-gst-einvoicing-itc",
                title: "GST E-Invoicing & ITC 2B Reconciliation: Avoiding Audit Notices",
                summary: "New strict audit rules on Form GSTR-1A, auto-generated GSTR-2B ITC matching, and avoiding 100% ITC disallowance under Section 16(2)(aa).",
                category: "GST & Direct Taxes",
                categoryColor: Color(red: 16/255, green: 185/255, blue: 129/255),
                readTime: "5 min read",
                publishDate: "Mar 2026",
                icon: "doc.plaintext.fill",
                keyTakeaways: [
                    "E-Invoicing mandatory for B2B transactions above ₹5 Cr threshold",
                    "Input Tax Credit (ITC) strictly restricted to invoices in GSTR-2B",
                    "Form GSTR-1A introduces pre-filing amendment facility",
                    "Automated Rule 88C / 88D notices issued for tax & ITC variances"
                ],
                fullArticle: """
                The GST Network (GSTN) has rolled out rigorous automated reconciliation mechanisms that directly impact monthly cash flows and input tax credits.
                
                1. Mandatory E-Invoicing Thresholds:
                Businesses with aggregate annual turnover exceeding ₹5 Crores must generate Invoice Reference Numbers (IRN) and signed QR codes via the IRP portal for all B2B invoices and debit/credit notes. Invoices without valid IRN are legally invalid.
                
                2. 100% GSTR-2B Matching Rule:
                Under Section 16(2)(aa), no taxpayer can claim ITC unless the supplier has uploaded the invoice in their GSTR-1 and it is reflected in the recipient's GSTR-2B.
                
                3. Automated DRC-01B & DRC-01C Notices:
                Variances between GSTR-1 vs GSTR-3B tax liability, or GSTR-2B vs GSTR-3B ITC claimed exceeding threshold percentages automatically generate DRC-01B/C notices requiring reconciliation within 7 days.
                
                4. Best Practices:
                Run monthly supplier reconciliation reports, verify GSTIN statuses, and utilize VR Here Bookkeeping & GST Filing modules for automated verification.
                """,
                coverImageUrl: "https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=800&auto=format&fit=crop&q=80"
            ),
            BlogPostItem(
                id: "blog-startup-india-80iac",
                title: "Startup India 80-IAC 3-Year Tax Holiday & IMB Approval Guide",
                summary: "Step-by-step checklist to secure Inter-Ministerial Board (IMB) approval for 100% income tax exemption and collateral-free bank funding.",
                category: "Startups & Funding",
                categoryColor: Color(red: 99/255, green: 102/255, blue: 241/255),
                readTime: "6 min read",
                publishDate: "Feb 2026",
                icon: "airplane.departure",
                keyTakeaways: [
                    "100% tax exemption on profits for 3 consecutive years out of 10",
                    "Entity must be Private Limited or LLP incorporated after April 1, 2016",
                    "Turnover must not exceed ₹100 Crores in any financial year",
                    "Requires innovative business model approved by Inter-Ministerial Board"
                ],
                fullArticle: """
                The Startup India initiative by the Department for Promotion of Industry and Internal Trade (DPIIT) offers transformative tax exemptions and funding benefits for eligible Indian startups.
                
                1. Section 80-IAC Benefits:
                Eligible startups can choose a 3-consecutive-year 100% tax holiday from their first 10 years of incorporation. This frees substantial capital for reinvestment into product R&D, scaling operations, and hiring talent.
                
                2. Eligibility Criteria:
                - Must be incorporated as a Private Limited Company or LLP.
                - Turnover must not have exceeded ₹100 Crores in any previous year.
                - Must be working towards innovation, development, or commercialization of new products or processes.
                
                3. Inter-Ministerial Board (IMB) Application:
                DPIIT recognition is the first step; obtaining Section 80-IAC certification requires pitching business model uniqueness, patent/IP portfolios, and audited projections to the IMB committee.
                
                4. Additional Perks:
                80% rebate on Patent filing fees, 50% rebate on Trademark fees, access to CGTMSE collateral-free credit guarantee loans up to ₹5 Crores, and self-certification under 6 labor and 3 environmental laws.
                """,
                coverImageUrl: "https://images.unsplash.com/photo-1519389950473-47ba0277781c?w=800&auto=format&fit=crop&q=80"
            ),
            BlogPostItem(
                id: "blog-trademark-classes",
                title: "Trademark Classes & Brand Protection: Preventing Infringement",
                summary: "How to accurately classify multi-class trademark applications (TM-A) across 45 NICE classes to protect logos, names, and software brands.",
                category: "IPR & Legal",
                categoryColor: Color(red: 245/255, green: 158/255, blue: 11/255),
                readTime: "3 min read",
                publishDate: "Feb 2026",
                icon: "shield.fill",
                keyTakeaways: [
                    "45 NICE Classification classes (Classes 1-34 Goods, 35-45 Services)",
                    "Class 35 covers retail, wholesale, e-commerce, and digital marketplaces",
                    "Class 42 covers SaaS, software development, and cloud IT services",
                    "TM symbol can be used immediately on filing; ® only upon registration certificate"
                ],
                fullArticle: """
                A trademark protects your unique brand identity, brand reputation, and prevents competitors from using deceptively similar names, logos, or slogans.
                
                1. The NICE Classification System:
                Trademark applications are categorized into 45 distinct classes. Selecting incorrect classes leaves your actual core revenue streams vulnerable to competitor squatting and infringement.
                
                2. Key Classes for Modern Businesses:
                - Class 35: Advertising, business management, retail, and e-commerce distribution.
                - Class 42: Software as a Service (SaaS), IT solutions, technology hosting, and design.
                - Class 9: Mobile applications, downloadable software, and electronics.
                - Class 41: Education, training, entertainment, and digital media production.
                """,
                coverImageUrl: "https://images.unsplash.com/photo-1450133064473-71024230f91b?w=800&auto=format&fit=crop&q=80"
            )
        ]
    }
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(spacing: 18) {
                
                // =========================================================================
                // 1. TOP GREETING & SEARCH BAR WITH GLOWING BACKDROP MATCHING ANDROID 1:1
                // =========================================================================
                VStack(alignment: .leading, spacing: 12) {
                    // Greeting text
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text("Welcome, \(userName.isEmpty ? "Valued Client" : userName)")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(.textDark)
                                .tracking(-0.5)
                            Text("👋")
                                .font(.system(size: 20))
                        }
                        
                        Text("Here is an executive snapshot of your filings, compliance status, and vault.")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.textMuted)
                            .padding(.top, 2)
                    }
                    
                    // Glowing Search Input Container
                    VStack(spacing: 0) {
                        HStack(spacing: 10) {
                            Image(systemName: "magnifyingglass")
                                .font(.system(size: 16, weight: .bold))
                                .foregroundColor(.primaryRed)
                            
                            TextField("Search any service or filing...", text: $searchQuery)
                                .font(.system(size: 13, weight: .medium))
                                .foregroundColor(.textDark)
                                .onChange(of: searchQuery) { val in
                                    showSuggestions = !val.trimmingCharacters(in: .whitespaces).isEmpty
                                }
                            
                            if !searchQuery.isEmpty {
                                Button(action: {
                                    onSelectTab("Services")
                                    showSuggestions = false
                                }) {
                                    Text("FIND")
                                        .font(.system(size: 10, weight: .black))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 5)
                                        .background(Color.primaryRed)
                                        .cornerRadius(8)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 11)
                        .background(Color.white)
                        .cornerRadius(16)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                        .shadow(color: Color.primaryRed.opacity(0.12), radius: 8, x: 0, y: 3)
                        
                        // Autocomplete Suggestions Dropdown
                        if showSuggestions && !filteredSuggestions.isEmpty {
                            VStack(alignment: .leading, spacing: 0) {
                                ForEach(filteredSuggestions, id: \.self) { suggestion in
                                    Button(action: {
                                        let liveMap: [String: (String, String)] = [
                                            "Private Limited Company Registration": ("Private Limited Registration", "https://vrhere.in/pvt-ltd-registration"),
                                            "Limited Liability Partnership (LLP)": ("Partnership Firm", "https://vrhere.in/partnership-firm"),
                                            "GST Registration": ("GST Registration", "https://vrhere.in/gst-registration"),
                                            "Income Tax Return": ("Income Tax Return", "https://vrhere.in/income-tax-return"),
                                            "Company Annual Compliances": ("CCFS-2026 Scheme", "https://vrhere.in/compliance-scheme-2026")
                                        ]
                                        
                                        if let matched = liveMap[suggestion] {
                                            onOpenLiveService(matched.0, matched.1)
                                        } else {
                                            searchQuery = suggestion
                                            onSelectTab("Services")
                                        }
                                        showSuggestions = false
                                    }) {
                                        HStack {
                                            Text(suggestion)
                                                .font(.system(size: 12.5, weight: .semibold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            Image(systemName: "arrow.right")
                                                .font(.system(size: 12, weight: .bold))
                                                .foregroundColor(.primaryRed)
                                        }
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 10)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                    
                                    Divider().background(Color.borderLight)
                                }
                            }
                            .background(Color.white)
                            .cornerRadius(16)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.08), radius: 10, y: 4)
                            .padding(.top, 6)
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                
                // =========================================================================
                // 2. 4-KPI STAT CARDS (2x2 EXECUTIVE GRID) MATCHING ANDROID 1:1
                // =========================================================================
                VStack(spacing: 10) {
                    // Row 1: Active Orders & Action Needed
                    HStack(spacing: 10) {
                        // KPI 1: Active Orders
                        Button(action: { onSelectTab("Orders") }) {
                            VStack(alignment: .leading, spacing: 0) {
                                HStack {
                                    Text("ACTIVE ORDERS")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.textMuted)
                                        .tracking(0.5)
                                    Spacer()
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(Color.primaryRed.opacity(0.10))
                                            .frame(width: 30, height: 30)
                                        Image(systemName: "briefcase.fill")
                                            .font(.system(size: 14))
                                            .foregroundColor(.primaryRed)
                                    }
                                }
                                
                                Spacer().frame(height: 8)
                                
                                HStack(alignment: .bottom) {
                                    Text("\(activeOrders.count)")
                                        .font(.system(size: 22, weight: .black))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text("Track →")
                                        .font(.system(size: 10.5, weight: .bold))
                                        .foregroundColor(.primaryRed)
                                }
                                
                                Text("In-progress filings")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                                    .padding(.top, 2)
                            }
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.white)
                            .cornerRadius(18)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        // KPI 2: Action Needed
                        let hasPending = !pendingActions.isEmpty
                        Button(action: { onSelectTab("Orders") }) {
                            VStack(alignment: .leading, spacing: 0) {
                                HStack {
                                    Text("ACTION NEEDED")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(hasPending ? Color(red: 225/255, green: 29/255, blue: 72/255) : .textMuted)
                                        .tracking(0.5)
                                    Spacer()
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(hasPending ? Color(red: 255/255, green: 228/255, blue: 230/255) : Color.bgInput)
                                            .frame(width: 30, height: 30)
                                        Image(systemName: "exclamationmark.triangle.fill")
                                            .font(.system(size: 14))
                                            .foregroundColor(hasPending ? Color(red: 225/255, green: 29/255, blue: 72/255) : .textMuted)
                                    }
                                }
                                
                                Spacer().frame(height: 8)
                                
                                HStack(alignment: .bottom) {
                                    Text("\(pendingActions.count)")
                                        .font(.system(size: 22, weight: .black))
                                        .foregroundColor(hasPending ? Color(red: 190/255, green: 18/255, blue: 60/255) : .textDark)
                                    Spacer()
                                    Text("Upload →")
                                        .font(.system(size: 10.5, weight: .bold))
                                        .foregroundColor(hasPending ? Color(red: 225/255, green: 29/255, blue: 72/255) : .textMuted)
                                }
                                
                                Text("Pending proofs")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                                    .padding(.top, 2)
                            }
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(hasPending ? Color(red: 255/255, green: 241/255, blue: 242/255) : Color.white)
                            .cornerRadius(18)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(hasPending ? Color(red: 254/255, green: 205/255, blue: 211/255) : Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    
                    // Row 2: Digital Vault & Total Portfolio / Due Balance
                    HStack(spacing: 10) {
                        // KPI 3: Digital Vault
                        Button(action: { onSelectTab("Vault") }) {
                            VStack(alignment: .leading, spacing: 0) {
                                HStack {
                                    Text("DIGITAL VAULT")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.textMuted)
                                        .tracking(0.5)
                                    Spacer()
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.10))
                                            .frame(width: 30, height: 30)
                                        Image(systemName: "folder.fill")
                                            .font(.system(size: 14))
                                            .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                                    }
                                }
                                
                                Spacer().frame(height: 8)
                                
                                HStack(alignment: .bottom) {
                                    let vaultCount = !completedOrders.isEmpty ? (completedOrders.count * 3 + 8) : 8
                                    Text("\(vaultCount)")
                                        .font(.system(size: 22, weight: .black))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text("Vault →")
                                        .font(.system(size: 10.5, weight: .bold))
                                        .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                                }
                                
                                Text("Verified documents")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                                    .padding(.top, 2)
                            }
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.white)
                            .cornerRadius(18)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        // KPI 4: Due Balance / Total Portfolio
                        let hasDue = totalOutstanding > 0
                        Button(action: { onSelectTab("Invoices") }) {
                            VStack(alignment: .leading, spacing: 0) {
                                HStack {
                                    Text(hasDue ? "DUE BALANCE" : "TOTAL PORTFOLIO")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(hasDue ? Color(red: 245/255, green: 158/255, blue: 11/255) : .textMuted)
                                        .tracking(0.5)
                                    Spacer()
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(hasDue ? Color(red: 254/255, green: 243/255, blue: 199/255) : Color(red: 37/255, green: 99/255, blue: 235/255).opacity(0.10))
                                            .frame(width: 30, height: 30)
                                        Image(systemName: "indianrupeesign")
                                            .font(.system(size: 14))
                                            .foregroundColor(hasDue ? Color(red: 245/255, green: 158/255, blue: 11/255) : Color(red: 37/255, green: 99/255, blue: 235/255))
                                    }
                                }
                                
                                Spacer().frame(height: 8)
                                
                                HStack(alignment: .bottom) {
                                    if hasDue {
                                        Text("₹\(Int(totalOutstanding))")
                                            .font(.system(size: 20, weight: .black))
                                            .foregroundColor(Color(red: 146/255, green: 64/255, blue: 14/255))
                                        Spacer()
                                        Text("Pay →")
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(Color(red: 245/255, green: 158/255, blue: 11/255))
                                    } else {
                                        let volumeK = totalVolume / 1000.0
                                        Text(String(format: "₹%.1fk", volumeK))
                                            .font(.system(size: 22, weight: .black))
                                            .foregroundColor(.textDark)
                                        Spacer()
                                        Text("Bills →")
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(Color(red: 37/255, green: 99/255, blue: 235/255))
                                    }
                                }
                                
                                Text(hasDue ? "\(unpaidOrders.count) pending payment(s)" : "Settled volume")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                                    .padding(.top, 2)
                            }
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(hasDue ? Color(red: 255/255, green: 251/255, blue: 235/255) : Color.white)
                            .cornerRadius(18)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(hasDue ? Color(red: 253/255, green: 230/255, blue: 138/255) : Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 3. FEATURED OFFERS & SCHEMES AUTO-SLIDING CAROUSEL BANNER
                // =========================================================================
                VStack(spacing: 8) {
                    HStack {
                        HStack(spacing: 6) {
                            Image(systemName: "tag.fill")
                                .font(.system(size: 14))
                                .foregroundColor(.primaryRed)
                            Text("Featured Offers & Schemes")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        
                        Spacer()
                        
                        // Dot Indicators
                        HStack(spacing: 5) {
                            ForEach(0..<promoOffers.count, id: \.self) { idx in
                                let isSel = currentPromoIndex == idx
                                RoundedRectangle(cornerRadius: 3)
                                    .fill(isSel ? Color.primaryRed : Color.borderLight)
                                    .frame(width: isSel ? 18 : 6, height: 6)
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                    
                    TabView(selection: $currentPromoIndex) {
                        ForEach(Array(promoOffers.enumerated()), id: \.element.id) { index, offer in
                            Button(action: {
                                if let url = offer.liveServiceUrl, let name = offer.liveServiceName {
                                    onOpenLiveService(name, url)
                                } else {
                                    onSelectTab(offer.targetTab)
                                }
                            }) {
                                ZStack {
                                    if let imgUrl = offer.bannerImageUrl, let url = imgUrl.asImageURL {
                                        AsyncImage(url: url) { phase in
                                            switch phase {
                                            case .success(let image):
                                                image
                                                    .resizable()
                                                    .scaledToFill()
                                            default:
                                                LinearGradient(colors: offer.bgColors, startPoint: .topLeading, endPoint: .bottomTrailing)
                                            }
                                        }
                                        
                                        LinearGradient(
                                            colors: [Color.black.opacity(0.45), Color.black.opacity(0.88)],
                                            startPoint: .top,
                                            endPoint: .bottom
                                        )
                                    } else {
                                        LinearGradient(colors: offer.bgColors, startPoint: .topLeading, endPoint: .bottomTrailing)
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 0) {
                                        // Header row inside card
                                        HStack {
                                            Text(offer.tag.uppercased())
                                                .font(.system(size: 9, weight: .black))
                                                .foregroundColor(.white)
                                                .tracking(0.8)
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 3.5)
                                                .background(offer.accentColor.opacity(0.85))
                                                .cornerRadius(20)
                                            
                                            Spacer()
                                            
                                            Text(offer.badge)
                                                .font(.system(size: 9, weight: .black))
                                                .foregroundColor(.white)
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 3.5)
                                                .background(Color.white.opacity(0.20))
                                                .cornerRadius(8)
                                        }
                                        
                                        Spacer()
                                        
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(offer.title)
                                                .font(.system(size: 15, weight: .black))
                                                .foregroundColor(.white)
                                                .lineLimit(1)
                                            
                                            Text(offer.description)
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 226/255, green: 232/255, blue: 240/255))
                                                .lineLimit(2)
                                                .lineSpacing(2)
                                        }
                                        
                                        Spacer()
                                        
                                        HStack(alignment: .center) {
                                            if offer.discountedPrice > 0 {
                                                HStack(alignment: .bottom, spacing: 6) {
                                                    Text("₹\(Int(offer.discountedPrice))")
                                                        .font(.system(size: 14, weight: .black))
                                                        .foregroundColor(.white)
                                                    
                                                    if offer.originalPrice > offer.discountedPrice {
                                                        Text("₹\(Int(offer.originalPrice))")
                                                            .font(.system(size: 10))
                                                            .foregroundColor(Color.slate400)
                                                            .strikethrough()
                                                    }
                                                }
                                            } else {
                                                Text("Tap to apply")
                                                    .font(.system(size: 10, weight: .medium))
                                                    .foregroundColor(Color.slate400)
                                            }
                                            
                                            Spacer()
                                            
                                            Text(offer.ctaText)
                                                .font(.system(size: 11, weight: .black))
                                                .foregroundColor(.white)
                                                .padding(.horizontal, 12)
                                                .padding(.vertical, 6)
                                                .background(offer.accentColor)
                                                .cornerRadius(10)
                                        }
                                    }
                                    .padding(16)
                                }
                                .frame(height: 168)
                                .cornerRadius(22)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 22)
                                        .stroke(offer.accentColor.opacity(0.35), lineWidth: 1)
                                )
                                .shadow(color: Color.black.opacity(0.12), radius: 6, y: 3)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                            .tag(index)
                            .padding(.horizontal, 16)
                        }
                    }
                    .frame(height: 172)
                    .tabViewStyle(PageTabViewStyle(indexDisplayMode: .never))
                }
                .onAppear {
                    timerSubscription = Timer.publish(every: 4.0, on: .main, in: .common)
                        .autoconnect()
                        .sink { _ in
                            withAnimation(.easeInOut(duration: 0.5)) {
                                currentPromoIndex = (currentPromoIndex + 1) % max(1, promoOffers.count)
                            }
                        }
                }
                .onDisappear {
                    timerSubscription?.cancel()
                }
                
                // =========================================================================
                // 4. ENTERPRISE CLIENT HUB HERO BANNER MATCHING ANDROID 1:1
                // =========================================================================
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("ENTERPRISE CLIENT HUB")
                            .font(.system(size: 9.5, weight: .black))
                            .foregroundColor(Color(red: 255/255, green: 128/255, blue: 128/255))
                            .tracking(0.8)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(Color.primaryRed.opacity(0.25))
                            .cornerRadius(20)
                            .overlay(
                                RoundedRectangle(cornerRadius: 20)
                                    .stroke(Color.primaryRed.opacity(0.4), lineWidth: 1)
                            )
                        
                        Spacer()
                        
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 13))
                                .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                            Text("Real-Time MCA Sync")
                                .font(.system(size: 10.5, weight: .bold))
                                .foregroundColor(Color.slate400)
                        }
                    }
                    
                    Text("Manage Filings, Upload Vault Docs & Track Milestones")
                        .font(.system(size: 17, weight: .black))
                        .foregroundColor(.white)
                        .lineSpacing(4)
                    
                    Text("All filings and compliance submissions are managed directly by your assigned dedicated advisor and operations team.")
                        .font(.system(size: 11.5))
                        .foregroundColor(Color.slate400)
                        .lineSpacing(3)
                    
                    HStack(spacing: 10) {
                        Button(action: { onSelectTab("Orders") }) {
                            HStack(spacing: 6) {
                                Text("View Pipeline (\(activeOrders.count))")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.white)
                                Image(systemName: "arrow.right")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.white)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(Color.primaryRed)
                            .cornerRadius(12)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        Button(action: { onSelectTab("Services") }) {
                            Text("Catalog")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 10)
                                .background(Color.white.opacity(0.12))
                                .cornerRadius(12)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(Color.white.opacity(0.2), lineWidth: 1)
                                )
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
                .padding(20)
                .background(Color.darkSlate)
                .cornerRadius(24)
                .overlay(
                    RoundedRectangle(cornerRadius: 24)
                        .stroke(Color.white.opacity(0.12), lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.2), radius: 12, y: 4)
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 4.5 PENDING INVOICES & OUTSTANDING BALANCE ATTENTION CARD (IF ANY)
                // =========================================================================
                if !unpaidOrders.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color.primaryRed)
                                    .frame(width: 36, height: 36)
                                Image(systemName: "wallet.pass.fill")
                                    .font(.system(size: 16))
                                    .foregroundColor(.white)
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Pending Invoices & Payment Due")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(Color(red: 153/255, green: 27/255, blue: 27/255))
                                Text("Total Outstanding: ₹\(Int(totalOutstanding))")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.primaryRed)
                            }
                        }
                        
                        ForEach(Array(unpaidOrders.prefix(3))) { order in
                            let balanceDue = Int(order.price)
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(order.serviceName)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                        .lineLimit(1)
                                    Text("Balance Due: ₹\(balanceDue)")
                                        .font(.system(size: 10.5, weight: .black))
                                        .foregroundColor(.primaryRed)
                                }
                                
                                Spacer()
                                
                                Button(action: { onOpenProject(order.id) }) {
                                    Text("Pay ₹\(balanceDue)")
                                        .font(.system(size: 10.5, weight: .black))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 6)
                                        .background(Color.primaryRed)
                                        .cornerRadius(10)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(12)
                            .background(Color.white)
                            .cornerRadius(14)
                            .overlay(
                                RoundedRectangle(cornerRadius: 14)
                                    .stroke(Color(red: 254/255, green: 226/255, blue: 226/255), lineWidth: 1)
                            )
                        }
                    }
                    .padding(16)
                    .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                    .cornerRadius(20)
                    .overlay(
                        RoundedRectangle(cornerRadius: 20)
                            .stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1)
                    )
                    .padding(.horizontal, 16)
                }
                
                // =========================================================================
                // 5. ACTION ITEMS REQUIRING ATTENTION (IF ANY)
                // =========================================================================
                if !pendingActions.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color(red: 245/255, green: 158/255, blue: 11/255))
                                    .frame(width: 36, height: 36)
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.system(size: 16))
                                    .foregroundColor(.black)
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Action Items Require Attention")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(Color(red: 120/255, green: 53/255, blue: 15/255))
                                Text("\(pendingActions.count) order(s) waiting for document uploads or clarification.")
                                    .font(.system(size: 10.5))
                                    .foregroundColor(Color(red: 146/255, green: 64/255, blue: 14/255))
                            }
                        }
                        
                        ForEach(Array(pendingActions.prefix(2))) { order in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(order.serviceName)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(order.status)
                                        .font(.system(size: 10, weight: .semibold))
                                        .foregroundColor(Color(red: 180/255, green: 83/255, blue: 9/255))
                                }
                                
                                Spacer()
                                
                                Button(action: { onOpenProject(order.id) }) {
                                    Text("Take Action →")
                                        .font(.system(size: 10, weight: .black))
                                        .foregroundColor(.black)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 5)
                                        .background(Color(red: 245/255, green: 158/255, blue: 11/255))
                                        .cornerRadius(8)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(12)
                            .background(Color.white)
                            .cornerRadius(12)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(Color(red: 253/255, green: 230/255, blue: 138/255), lineWidth: 1)
                            )
                        }
                    }
                    .padding(16)
                    .background(Color(red: 255/255, green: 251/255, blue: 235/255))
                    .cornerRadius(20)
                    .overlay(
                        RoundedRectangle(cornerRadius: 20)
                            .stroke(Color(red: 253/255, green: 230/255, blue: 138/255), lineWidth: 1)
                    )
                    .padding(.horizontal, 16)
                }
                
                // =========================================================================
                // 6. ACTIVE OPERATIONAL PIPELINE SNAPSHOT MATCHING ANDROID 1:1
                // =========================================================================
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Active Operational Pipeline")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            Text("Live stage progress for ongoing filings")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        
                        Spacer()
                        
                        Button(action: { onSelectTab("Orders") }) {
                            Text("All Orders →")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    
                    if activeOrders.isEmpty {
                        VStack(spacing: 8) {
                            ZStack {
                                Circle()
                                    .fill(Color.bgInput)
                                    .frame(width: 44, height: 44)
                                Image(systemName: "briefcase.fill")
                                    .font(.system(size: 18))
                                    .foregroundColor(.textMuted)
                            }
                            
                            Text("No Active Engagements")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            
                            Text("Explore our catalog to start a new company incorporation, GST, or compliance filing.")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 16)
                            
                            Button(action: { onSelectTab("Services") }) {
                                Text("Browse Services")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 8)
                                    .background(Color.darkSlate)
                                    .cornerRadius(10)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                            .padding(.top, 4)
                        }
                        .padding(24)
                        .frame(maxWidth: .infinity)
                        .background(Color.white)
                        .cornerRadius(18)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    } else {
                        ForEach(Array(activeOrders.prefix(3))) { proj in
                            let progress = getStatusProgress(proj.status)
                            Button(action: { onOpenProject(proj.id) }) {
                                VStack(alignment: .leading, spacing: 10) {
                                    HStack(alignment: .top) {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(proj.serviceName)
                                                .font(.system(size: 13.5, weight: .black))
                                                .foregroundColor(.textDark)
                                                .lineLimit(1)
                                            Text(proj.packageName?.isEmpty ?? true ? "Standard Execution" : proj.packageName!)
                                                .font(.system(size: 10.5, weight: .bold))
                                                .foregroundColor(.textMuted)
                                        }
                                        
                                        Spacer()
                                        
                                        StatusBadge(status: proj.status)
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Text("MILESTONE PROGRESS")
                                                .font(.system(size: 9, weight: .black))
                                                .foregroundColor(.textMuted)
                                                .tracking(0.5)
                                            Spacer()
                                            Text("\(progress)%")
                                                .font(.system(size: 10.5, weight: .black))
                                                .foregroundColor(.primaryRed)
                                        }
                                        
                                        GeometryReader { geo in
                                            ZStack(alignment: .leading) {
                                                Capsule()
                                                    .fill(Color.bgInput)
                                                    .frame(height: 5)
                                                Capsule()
                                                    .fill(Color.primaryRed)
                                                    .frame(width: max(5, geo.size.width * CGFloat(progress) / 100.0), height: 5)
                                            }
                                        }
                                        .frame(height: 5)
                                    }
                                    
                                    HStack {
                                        Text("ID: #\(String(proj.id.suffix(6)).uppercased())")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.textMuted)
                                        Spacer()
                                        Text("Details →")
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(.primaryRed)
                                    }
                                }
                                .padding(16)
                                .background(Color.white)
                                .cornerRadius(18)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 18)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                    }
                }
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 7. QUICK ACTION LAUNCHPAD (8 SERVICES BENTO GRID, 4x2) MATCHING ANDROID
                // =========================================================================
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Quick Action Launchpad")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            Text("One-click jump to frequent requirements")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        
                        Spacer()
                        
                        Button(action: { onSelectTab("Services") }) {
                            Text("Catalog →")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    
                    // 4x2 Grid Layout
                    VStack(spacing: 12) {
                        ForEach(0..<2) { row in
                            HStack(spacing: 8) {
                                ForEach(0..<4) { col in
                                    let idx = row * 4 + col
                                    if idx < topServices.count {
                                        let service = topServices[idx]
                                        Button(action: {
                                            if let url = service.url {
                                                onOpenLiveService(service.name, url)
                                            } else {
                                                onSelectTab(service.targetTab)
                                            }
                                        }) {
                                            VStack(spacing: 6) {
                                                ZStack {
                                                    RoundedRectangle(cornerRadius: 12)
                                                        .fill(service.iconBg)
                                                        .frame(width: 42, height: 42)
                                                    Image(systemName: service.icon)
                                                        .font(.system(size: 18))
                                                        .foregroundColor(service.iconTint)
                                                }
                                                
                                                Text(service.name)
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(.textDark)
                                                    .lineLimit(1)
                                                    .multilineTextAlignment(.center)
                                                
                                                Text(service.tag)
                                                    .font(.system(size: 8.5, weight: .medium))
                                                    .foregroundColor(.textMuted)
                                                    .lineLimit(1)
                                                    .multilineTextAlignment(.center)
                                            }
                                            .padding(.vertical, 12)
                                            .padding(.horizontal, 4)
                                            .frame(maxWidth: .infinity)
                                            .background(Color.bgLight)
                                            .cornerRadius(14)
                                            .overlay(
                                                RoundedRectangle(cornerRadius: 14)
                                                    .stroke(Color.borderLight, lineWidth: 1)
                                            )
                                        }
                                        .buttonStyle(ScaleOnPressButtonStyle())
                                    }
                                }
                            }
                        }
                    }
                }
                .padding(18)
                .background(Color.white)
                .cornerRadius(24)
                .overlay(
                    RoundedRectangle(cornerRadius: 24)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 8. DEDICATED ADVISOR CARD MATCHING ANDROID 1:1
                // =========================================================================
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("DEDICATED ADVISOR")
                            .font(.system(size: 9.5, weight: .black))
                            .foregroundColor(Color.slate400)
                            .tracking(0.8)
                        
                        Spacer()
                        
                        Text("Available")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color(red: 16/255, green: 185/255, blue: 129/255).opacity(0.20))
                            .cornerRadius(12)
                    }
                    
                    HStack(spacing: 12) {
                        ZStack {
                            Circle()
                                .fill(
                                    LinearGradient(
                                        colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 79/255, green: 70/255, blue: 229/255)],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .frame(width: 44, height: 44)
                            Text("CA")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.white)
                        }
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Dedicated CA Advisory Team")
                                .font(.system(size: 13.5, weight: .bold))
                                .foregroundColor(.white)
                            Text("Senior Chartered Accountant")
                                .font(.system(size: 11))
                                .foregroundColor(Color.slate400)
                        }
                    }
                    
                    Text("Need priority clarification on your filing or requirements? Reach your dedicated advisor directly.")
                        .font(.system(size: 11.5))
                        .foregroundColor(Color.slate400)
                        .lineSpacing(3)
                    
                    HStack(spacing: 10) {
                        Button(action: {
                            if let url = URL(string: "tel:918008530606") {
                                openURL(url)
                            }
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "phone.fill")
                                    .font(.system(size: 12))
                                Text("Call Advisor")
                                    .font(.system(size: 11, weight: .bold))
                            }
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(Color.white.opacity(0.12))
                            .cornerRadius(10)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        Button(action: {
                            if let url = URL(string: "https://wa.me/918008530606") {
                                openURL(url)
                            }
                        }) {
                            Text("WhatsApp")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 9)
                                .background(Color(red: 34/255, green: 197/255, blue: 94/255))
                                .cornerRadius(10)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
                .padding(18)
                .background(Color.darkSlate)
                .cornerRadius(22)
                .overlay(
                    RoundedRectangle(cornerRadius: 22)
                        .stroke(Color.white.opacity(0.12), lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.15), radius: 6, y: 2)
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 9. STATUTORY COMPLIANCE CALENDAR MATCHING ANDROID 1:1
                // =========================================================================
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        HStack(spacing: 6) {
                            Image(systemName: "calendar")
                                .font(.system(size: 15))
                                .foregroundColor(.primaryRed)
                            Text("Compliance Calendar")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        Spacer()
                        Text("March 2026")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                    
                    VStack(spacing: 8) {
                        // Compliance 1: GST-3B
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("GST-3B Filing")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Monthly Return")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("20th Mar")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.primaryRed)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                .cornerRadius(6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(red: 254/255, green: 202/255, blue: 202/255), lineWidth: 1)
                                )
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color.bgLight)
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                        
                        // Compliance 2: Advance Tax
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Advance Tax Q4")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Direct Tax Installment")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("15th Mar")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(Color(red: 245/255, green: 158/255, blue: 11/255))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 255/255, green: 251/255, blue: 235/255))
                                .cornerRadius(6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(red: 253/255, green: 230/255, blue: 138/255), lineWidth: 1)
                                )
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color.bgLight)
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                        
                        // Compliance 3: CCFS Amnesty
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("CCFS-2026 Amnesty")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("ROC Late Filing Waiver")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("Active")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(Color(red: 16/255, green: 185/255, blue: 129/255))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                                .cornerRadius(6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                                )
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color.bgLight)
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                }
                .padding(18)
                .background(Color.white)
                .cornerRadius(22)
                .overlay(
                    RoundedRectangle(cornerRadius: 22)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 10. REFER & EARN REWARD CARD MATCHING ANDROID 1:1
                // =========================================================================
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 10) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 10)
                                .fill(Color(red: 245/255, green: 158/255, blue: 11/255))
                                .frame(width: 36, height: 36)
                            Image(systemName: "gift.fill")
                                .font(.system(size: 18))
                                .foregroundColor(.white)
                        }
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Refer & Earn ₹500")
                                .font(.system(size: 13.5, weight: .black))
                                .foregroundColor(Color(red: 120/255, green: 53/255, blue: 15/255))
                            Text("Instant wallet credits per referral")
                                .font(.system(size: 10.5))
                                .foregroundColor(Color(red: 146/255, green: 64/255, blue: 14/255))
                        }
                    }
                    
                    Text("Refer another founder for company registration or ISO certification and receive ₹500 credit on your next filing.")
                        .font(.system(size: 11.5))
                        .foregroundColor(Color(red: 120/255, green: 53/255, blue: 15/255).opacity(0.85))
                        .lineSpacing(3)
                    
                    Button(action: { onSelectTab("Referrals") }) {
                        Text("Get Referral Link")
                            .font(.system(size: 11.5, weight: .bold))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(Color.darkSlate)
                            .cornerRadius(10)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(18)
                .background(Color(red: 255/255, green: 251/255, blue: 235/255))
                .cornerRadius(22)
                .overlay(
                    RoundedRectangle(cornerRadius: 22)
                        .stroke(Color(red: 253/255, green: 230/255, blue: 138/255), lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                .padding(.horizontal, 16)
                
                // =========================================================================
                // 11. LATEST REGULATORY UPDATES & INSIGHTS (BLOG SECTION) MATCHING ANDROID
                // =========================================================================
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        HStack(spacing: 6) {
                            Image(systemName: "book.closed.fill")
                                .font(.system(size: 15))
                                .foregroundColor(.primaryRed)
                            Text("Compliance Insights & News")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        Spacer()
                    }
                    
                    Text("Expert articles & statutory notifications")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                        .padding(.top, -8)
                    
                    VStack(spacing: 10) {
                        ForEach(blogPosts) { post in
                            Button(action: { selectedBlogPost = post }) {
                                HStack(alignment: .top, spacing: 12) {
                                    if let imgUrl = post.coverImageUrl, let url = imgUrl.asImageURL {
                                        AsyncImage(url: url) { phase in
                                            switch phase {
                                            case .success(let image):
                                                image
                                                    .resizable()
                                                    .scaledToFill()
                                            default:
                                                ZStack {
                                                    post.categoryColor.opacity(0.12)
                                                    Image(systemName: post.icon)
                                                        .foregroundColor(post.categoryColor)
                                                }
                                            }
                                        }
                                        .frame(width: 64, height: 64)
                                        .cornerRadius(14)
                                        .clipped()
                                    } else {
                                        ZStack {
                                            RoundedRectangle(cornerRadius: 12)
                                                .fill(post.categoryColor.opacity(0.12))
                                                .frame(width: 42, height: 42)
                                            Image(systemName: post.icon)
                                                .font(.system(size: 18))
                                                .foregroundColor(post.categoryColor)
                                        }
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Text(post.category)
                                                .font(.system(size: 8.5, weight: .black))
                                                .foregroundColor(post.categoryColor)
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(post.categoryColor.opacity(0.12))
                                                .cornerRadius(6)
                                            
                                            Spacer()
                                            
                                            HStack(spacing: 4) {
                                                Text(post.readTime)
                                                    .font(.system(size: 9, weight: .medium))
                                                    .foregroundColor(.textMuted)
                                                Text("•")
                                                    .font(.system(size: 9))
                                                    .foregroundColor(.textMuted)
                                                Text(post.publishDate)
                                                    .font(.system(size: 9, weight: .medium))
                                                    .foregroundColor(.textMuted)
                                            }
                                        }
                                        
                                        Text(post.title)
                                            .font(.system(size: 12.5, weight: .bold))
                                            .foregroundColor(.textDark)
                                            .lineLimit(2)
                                            .multilineTextAlignment(.leading)
                                        
                                        Text(post.summary)
                                            .font(.system(size: 10.5))
                                            .foregroundColor(.textMuted)
                                            .lineLimit(2)
                                            .multilineTextAlignment(.leading)
                                        
                                        Text("Read Full Article →")
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(.primaryRed)
                                            .padding(.top, 2)
                                    }
                                }
                                .padding(14)
                                .background(Color.bgLight)
                                .cornerRadius(16)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                    }
                }
                .padding(18)
                .background(Color.white)
                .cornerRadius(24)
                .overlay(
                    RoundedRectangle(cornerRadius: 24)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                .padding(.horizontal, 16)
                
                Spacer().frame(height: 120)
            }
        }
        .background(Color.bgLight.ignoresSafeArea())
        .sheet(item: $selectedBlogPost) { post in
            BlogPostReaderModal(post: post, onExploreServices: {
                selectedBlogPost = nil
                onSelectTab("Services")
            })
        }
    }
}

// 12. Interactive Blog Post Reader Bottom Sheet Modal matching Android 1:1
struct BlogPostReaderModal: View {
    let post: BlogPostItem
    let onExploreServices: () -> Void
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let imgUrl = post.coverImageUrl, let url = imgUrl.asImageURL {
                        AsyncImage(url: url) { phase in
                            switch phase {
                            case .success(let image):
                                image
                                    .resizable()
                                    .scaledToFill()
                            default:
                                EmptyView()
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 150)
                        .cornerRadius(18)
                        .clipped()
                    }
                    
                    HStack {
                        Text(post.category)
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(post.categoryColor)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(post.categoryColor.opacity(0.15))
                            .cornerRadius(8)
                        
                        Spacer()
                        
                        HStack(spacing: 6) {
                            Text(post.readTime)
                                .font(.system(size: 10.5, weight: .medium))
                                .foregroundColor(.textMuted)
                            Text("•")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                            Text(post.publishDate)
                                .font(.system(size: 10.5, weight: .medium))
                                .foregroundColor(.textMuted)
                        }
                    }
                    
                    Text(post.title)
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .lineSpacing(4)
                    
                    Divider().background(Color.borderLight)
                    
                    // Key Takeaways Callout Card
                    if !post.keyTakeaways.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 6) {
                                Image(systemName: "checkmark.circle.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(post.categoryColor)
                                Text("KEY TAKEAWAYS & ACTION POINTS")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(post.categoryColor)
                                    .tracking(0.5)
                            }
                            
                            ForEach(post.keyTakeaways, id: \.self) { takeaway in
                                HStack(alignment: .top, spacing: 6) {
                                    Text("•")
                                        .font(.system(size: 12, weight: .black))
                                        .foregroundColor(post.categoryColor)
                                    Text(takeaway)
                                        .font(.system(size: 11.5, weight: .semibold))
                                        .foregroundColor(.textDark)
                                        .lineSpacing(2)
                                }
                            }
                        }
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(post.categoryColor.opacity(0.08))
                        .cornerRadius(16)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(post.categoryColor.opacity(0.25), lineWidth: 1)
                        )
                    }
                    
                    // Full Article Content
                    Text(post.fullArticle)
                        .font(.system(size: 13))
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                        .lineSpacing(5)
                        .padding(.vertical, 4)
                    
                    // Advisory Contact Footer
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Need assistance with this compliance?")
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(.white)
                        Text("Our chartered accountants and legal advocates are ready to handle the filing on your behalf.")
                            .font(.system(size: 11))
                            .foregroundColor(Color.slate400)
                            .lineSpacing(3)
                        
                        Button(action: onExploreServices) {
                            Text("Explore Filing Services")
                                .font(.system(size: 11.5, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(Color.primaryRed)
                                .cornerRadius(10)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        .padding(.top, 4)
                    }
                    .padding(16)
                    .background(Color.darkSlate)
                    .cornerRadius(16)
                }
                .padding(20)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Close") {
                        dismiss()
                    }
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.primaryRed)
                }
            }
        }
    }
}
