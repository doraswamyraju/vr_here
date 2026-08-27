import SwiftUI

struct ServiceItemModel: Identifiable {
    let id: String
    let title: String
    let categoryId: String
    let categoryName: String
    let iconName: String
    let colorTheme: Color
    let turnaround: String
    let startingPrice: String
    let trustBadge: String
    let targetUrl: String
}

struct CustomerServicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    let onSelectTab: (String) -> Void
    let onOpenLiveService: (String, String) -> Void
    
    @State private var searchQuery = ""
    @State private var selectedCategory: String = "ALL"
    
    private let categoriesList: [(id: String, name: String, icon: String)] = [
        ("ALL", "All Services", "square.grid.2x2.fill"),
        ("CORP", "Corporate Entity", "building.2.fill"),
        ("TAX", "Tax & Accounting", "percent"),
        ("ISO", "ISO & Quality", "checkmark.seal.fill"),
        ("LICENSE", "Licensing & Govt", "doc.plaintext.fill"),
        ("MSME", "MSME & Schemes", "globe"),
        ("STARTUP", "Industrial & Setup", "lightbulb.fill")
    ]
    
    private let allServicesList: [ServiceItemModel] = [
        // 1. Corporate Entity Registrations (8)
        ServiceItemModel(id: "pvt-ltd-registration", title: "Private Limited Company", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "building.2.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 7 Days", startingPrice: "From ₹5,499", trustBadge: "MCA Verified", targetUrl: "https://vrhere.in/pvt-ltd-registration"),
        ServiceItemModel(id: "public-limited-company", title: "Public Limited Company", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "building.columns.fill", colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255), turnaround: "⚡ 10-14 Days", startingPrice: "From ₹14,999", trustBadge: "MCA Verified", targetUrl: "https://vrhere.in/public-limited-company"),
        ServiceItemModel(id: "llp-registration", title: "Limited Liability Partnership (LLP)", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "person.2.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹4,899", trustBadge: "MCA Verified", targetUrl: "https://vrhere.in/llp-registration"),
        ServiceItemModel(id: "one-person-company", title: "One Person Company (OPC)", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "person.crop.circle.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹4,999", trustBadge: "Solo Founder", targetUrl: "https://vrhere.in/one-person-company"),
        ServiceItemModel(id: "partnership-firm", title: "Partnership Firm Registration", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "person.3.fill", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹3,499", trustBadge: "State ROF", targetUrl: "https://vrhere.in/partnership-firm"),
        ServiceItemModel(id: "section-8-company", title: "Section 8 Company (NGO)", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "heart.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ 10-12 Days", startingPrice: "From ₹8,499", trustBadge: "80G / 12A Ready", targetUrl: "https://vrhere.in/section-8-company"),
        ServiceItemModel(id: "society-trust-registration", title: "Society / Trust Registration", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "shield.lefthalf.filled", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 7-10 Days", startingPrice: "From ₹6,999", trustBadge: "Trust Deed", targetUrl: "https://vrhere.in/society-trust-registration"),
        ServiceItemModel(id: "proprietorship-setup", title: "Proprietorship Setup", categoryId: "CORP", categoryName: "Corporate Entity", iconName: "briefcase.fill", colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹1,999", trustBadge: "Fast Setup", targetUrl: "https://vrhere.in/proprietorship-setup"),

        // 2. Tax & Accounting Services (22)
        ServiceItemModel(id: "cloud-accounting", title: "Cloud Accounting (Tally, Zoho Books)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "chart.pie.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ Monthly Retainer", startingPrice: "From ₹2,999/mo", trustBadge: "Monthly MIS", targetUrl: "https://vrhere.in/cloud-accounting"),
        ServiceItemModel(id: "gst-return-filing", title: "GST Return Filing (GSTR 1, 3B, 9)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "arrow.triangle.2.circlepath.doc.on.clipboard", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ Monthly / Qtr", startingPrice: "From ₹499/mo", trustBadge: "Zero Penalty", targetUrl: "https://vrhere.in/gst-return-filing"),
        ServiceItemModel(id: "payroll-management", title: "Payroll Management & Payslips", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "person.text.rectangle", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ Monthly Cycle", startingPrice: "From ₹2,499/mo", trustBadge: "PF/ESI Compliant", targetUrl: "https://vrhere.in/payroll-management"),
        ServiceItemModel(id: "professional-tax", title: "Professional Tax (PTEC / PTRC)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "building.2.crop.circle", colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹1,999", trustBadge: "Commercial Taxes", targetUrl: "https://vrhere.in/professional-tax"),
        ServiceItemModel(id: "epf-esi-returns", title: "EPF & ESI Monthly Returns & ECR", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "person.3.sequence.fill", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ Monthly Cycle", startingPrice: "From ₹1,999/mo", trustBadge: "EPFO & ESIC", targetUrl: "https://vrhere.in/epf-esi-returns"),
        ServiceItemModel(id: "gratuity-management", title: "Gratuity Trust & Valuation", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "gift.fill", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹3,499", trustBadge: "Statutory Gratuity", targetUrl: "https://vrhere.in/gratuity-management"),
        ServiceItemModel(id: "tds-tcs-filing", title: "TDS / TCS Filing (24Q, 26Q, 27EQ)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "doc.text.below.ecg.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ Quarterly Filing", startingPrice: "From ₹1,999", trustBadge: "TRACES Verified", targetUrl: "https://vrhere.in/tds-tcs-filing"),
        ServiceItemModel(id: "inventory-stock-management", title: "Inventory & Stock Audit Ledgers", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "shippingbox.fill", colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255), turnaround: "⚡ Monthly / Qtr", startingPrice: "From ₹2,999", trustBadge: "Stock Verification", targetUrl: "https://vrhere.in/inventory-stock-management"),
        ServiceItemModel(id: "invoice-generation-support", title: "E-Invoicing & E-Way Bill Setup", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "doc.badge.arrow.up.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹1,499", trustBadge: "GST E-Invoice", targetUrl: "https://vrhere.in/invoice-generation-support"),
        ServiceItemModel(id: "expense-tracking-consultancy", title: "Expense Tracking & Cost Control", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "creditcard.and.123", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ Monthly Retainer", startingPrice: "From ₹1,999/mo", trustBadge: "Cost Reduction", targetUrl: "https://vrhere.in/expense-tracking-consultancy"),
        ServiceItemModel(id: "mis-reporting", title: "Monthly MIS & Financial Dashboards", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "chart.bar.xaxis", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ Monthly Reports", startingPrice: "From ₹3,999/mo", trustBadge: "CFO Advisory", targetUrl: "https://vrhere.in/mis-reporting"),
        ServiceItemModel(id: "compliance-scheme-2026", title: "Companies Compliance Scheme 2026 (CCFS)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "calendar.badge.clock", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ Fast Track", startingPrice: "From ₹4,999", trustBadge: "Immunity Scheme", targetUrl: "https://vrhere.in/compliance-scheme-2026"),
        ServiceItemModel(id: "gst-registration", title: "GST Registration Online", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "percent", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹2,569", trustBadge: "GSTIN Issued", targetUrl: "https://vrhere.in/gst-registration"),
        ServiceItemModel(id: "income-tax-return", title: "Income Tax Return Filing (ITR 1-7)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "indianrupeesign.circle.fill", colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255), turnaround: "⚡ 24-48 Hours", startingPrice: "From ₹1,499", trustBadge: "CA Certified", targetUrl: "https://vrhere.in/income-tax-return"),
        ServiceItemModel(id: "12aa-80g-certificates", title: "12A & 80G Tax Exemption Certificates", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "gift.fill", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ Form 10A/10AB", startingPrice: "From ₹6,999", trustBadge: "100% Tax Relief", targetUrl: "https://vrhere.in/12aa-80g-certificates"),
        ServiceItemModel(id: "tax-planning-support", title: "Corporate & Individual Tax Planning", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "lightbulb.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ Expert Call", startingPrice: "From ₹2,999", trustBadge: "Max Savings", targetUrl: "https://vrhere.in/tax-planning-support"),
        ServiceItemModel(id: "15ca-certification", title: "Form 15CA & 15CB Foreign Remittance", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "globe.americas.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹2,499", trustBadge: "CA Certificate", targetUrl: "https://vrhere.in/15ca-certification"),
        ServiceItemModel(id: "internal-audit", title: "Internal Financial Controls (IFC) Audit", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "doc.viewfinder.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ Comprehensive", startingPrice: "From ₹9,999", trustBadge: "Risk Mitigation", targetUrl: "https://vrhere.in/internal-audit"),
        ServiceItemModel(id: "gst-audit", title: "GST & GSTR-9C Reconciliation Audit", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "checkmark.seal.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ CA Certified", startingPrice: "From ₹9,999", trustBadge: "ITC Verified", targetUrl: "https://vrhere.in/gst-audit"),
        ServiceItemModel(id: "sox-audit", title: "SOX 404 Internal Controls Compliance", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "lock.square.fill", colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255), turnaround: "⚡ Enterprise", startingPrice: "From ₹19,999", trustBadge: "Global Standards", targetUrl: "https://vrhere.in/sox-audit"),
        ServiceItemModel(id: "stock-compliance-audit", title: "Physical Stock & Fixed Assets Audit", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "archivebox.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ On-Site / Remote", startingPrice: "From ₹7,999", trustBadge: "Bank Ready", targetUrl: "https://vrhere.in/stock-compliance-audit"),
        ServiceItemModel(id: "audit-services", title: "Statutory & Tax Audit (Sec 44AB)", categoryId: "TAX", categoryName: "Tax & Accounting", iconName: "signature", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ ICAI Standards", startingPrice: "From ₹9,999", trustBadge: "CA Practice", targetUrl: "https://vrhere.in/audit-services"),

        // 3. ISO & Quality Certifications (16)
        ServiceItemModel(id: "iso-9001-certification", title: "ISO 9001:2015 Quality Management", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "rosette", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹3,499", trustBadge: "IAF Accredited", targetUrl: "https://vrhere.in/iso-9001-certification"),
        ServiceItemModel(id: "iso-14001-certification", title: "ISO 14001:2015 Environmental (EMS)", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "leaf.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹5,499", trustBadge: "Green & ESG", targetUrl: "https://vrhere.in/iso-14001-certification"),
        ServiceItemModel(id: "iso-45001-certification", title: "ISO 45001:2018 Health & Safety (OH&S)", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "cross.case.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹5,999", trustBadge: "Workplace Safety", targetUrl: "https://vrhere.in/iso-45001-certification"),
        ServiceItemModel(id: "iso-22000-certification", title: "ISO 22000:2018 Food Safety (FSMS)", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "fork.knife.circle.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹6,999", trustBadge: "Food Safety", targetUrl: "https://vrhere.in/iso-22000-certification"),
        ServiceItemModel(id: "iso-27001-certification", title: "ISO 27001:2022 InfoSec & Cybersecurity", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "lock.shield.fill", colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255), turnaround: "⚡ 7-10 Days", startingPrice: "From ₹8,999", trustBadge: "Cyber Verified", targetUrl: "https://vrhere.in/iso-27001-certification"),
        ServiceItemModel(id: "iso-50001-certification", title: "ISO 50001:2018 Energy Management", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "bolt.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹7,999", trustBadge: "Energy Efficiency", targetUrl: "https://vrhere.in/iso-50001-certification"),
        ServiceItemModel(id: "iso-13485-certification", title: "ISO 13485:2016 Medical Devices", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "stethoscope", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ 7-10 Days", startingPrice: "From ₹9,999", trustBadge: "Medical Device", targetUrl: "https://vrhere.in/iso-13485-certification"),
        ServiceItemModel(id: "iso-20000-certification", title: "ISO 20000-1:2018 IT Service Management", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "server.rack", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹8,999", trustBadge: "ITSM Standard", targetUrl: "https://vrhere.in/iso-20000-certification"),
        ServiceItemModel(id: "iso-22301-certification", title: "ISO 22301:2019 Business Continuity", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "arrow.triangle.2.circlepath.circle.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹8,999", trustBadge: "Resilience", targetUrl: "https://vrhere.in/iso-22301-certification"),
        ServiceItemModel(id: "gmp-haccp-certification", title: "GMP & HACCP Certification", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "pills.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹6,499", trustBadge: "WHO-GMP", targetUrl: "https://vrhere.in/gmp-haccp-certification"),
        ServiceItemModel(id: "ce-marking-certification", title: "CE Marking for European Exports", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "globe.europe.africa.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 7-10 Days", startingPrice: "From ₹12,499", trustBadge: "EU Conformity", targetUrl: "https://vrhere.in/ce-marking-certification"),
        ServiceItemModel(id: "isi-bis-certification", title: "ISI Mark & BIS CRS Registration", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "star.circle.fill", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ 10-15 Days", startingPrice: "From ₹14,999", trustBadge: "Bureau Standards", targetUrl: "https://vrhere.in/isi-bis-certification"),
        ServiceItemModel(id: "fda-compliance-support", title: "US FDA Registration & Compliance", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "cross.fill", colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹14,999", trustBadge: "US FDA Ready", targetUrl: "https://vrhere.in/fda-compliance-support"),
        ServiceItemModel(id: "brcgs-certification", title: "BRCGS Global Food Standard", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "shield.lefthalf.filled.badge.checkmark", colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255), turnaround: "⚡ 10-12 Days", startingPrice: "From ₹14,999", trustBadge: "Global Retail", targetUrl: "https://vrhere.in/brcgs-certification"),
        ServiceItemModel(id: "kosher-certification", title: "Kosher Global Food Certification", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "sparkle", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹11,999", trustBadge: "Kosher Standard", targetUrl: "https://vrhere.in/kosher-certification"),
        ServiceItemModel(id: "halal-kosher-certification", title: "Halal & Kosher Export Certification", categoryId: "ISO", categoryName: "ISO & Quality", iconName: "sparkles", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹7,999", trustBadge: "Global Export", targetUrl: "https://vrhere.in/halal-kosher-certification"),

        // 4. Mandatory Licensing & Governance (28)
        ServiceItemModel(id: "udyam-registration", title: "Udyam MSME Registration Certificate", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "bolt.badge.a.fill", colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹999", trustBadge: "Ministry of MSME", targetUrl: "https://vrhere.in/udyam-registration"),
        ServiceItemModel(id: "shops-establishment-license", title: "Shops & Establishment Act License", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "storefront.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 2-4 Days", startingPrice: "From ₹1,499", trustBadge: "State Labour Dept", targetUrl: "https://vrhere.in/shops-establishment-license"),
        ServiceItemModel(id: "epfo-pf-registration", title: "EPFO (PF) Code Registration", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "person.badge.key.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹2,999", trustBadge: "EPFO Code", targetUrl: "https://vrhere.in/epfo-pf-registration"),
        ServiceItemModel(id: "esic-registration", title: "ESIC Employer Sub-Code Setup", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "cross.vial.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹2,999", trustBadge: "ESIC Code", targetUrl: "https://vrhere.in/esic-registration"),
        ServiceItemModel(id: "professional-tax-registration", title: "Professional Tax Registration (PT)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "building.2.crop.circle.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹1,999", trustBadge: "State Taxes", targetUrl: "https://vrhere.in/professional-tax-registration"),
        ServiceItemModel(id: "startup-india-registration", title: "Startup India DPIIT Recognition", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "flame.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹3,499", trustBadge: "3 Yr Tax Holiday", targetUrl: "https://vrhere.in/startup-india-registration"),
        ServiceItemModel(id: "import-export-code", title: "Import Export Code (IEC)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "airplane.departure", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹2,199", trustBadge: "DGFT Verified", targetUrl: "https://vrhere.in/import-export-code"),
        ServiceItemModel(id: "fssai-license", title: "FSSAI Food License / Registration", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "fork.knife", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹1,999", trustBadge: "FoSCoS Govt", targetUrl: "https://vrhere.in/fssai-license"),
        ServiceItemModel(id: "lei-certificate", title: "Legal Entity Identifier (LEI Code)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "number.circle.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 24-48 Hours", startingPrice: "From ₹4,999", trustBadge: "RBI / Global LEI", targetUrl: "https://vrhere.in/lei-certificate"),
        ServiceItemModel(id: "trade-license", title: "Municipal Trade License", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "building.2.crop.circle.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹2,499", trustBadge: "Municipal Corp", targetUrl: "https://vrhere.in/trade-license"),
        ServiceItemModel(id: "labour-license", title: "Contract Labour License (CLRA)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "person.3.sequence.fill", colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹5,499", trustBadge: "CLRA Act", targetUrl: "https://vrhere.in/labour-license"),
        ServiceItemModel(id: "pollution-noc", title: "Pollution Control Board NOC (CTE/CTO)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "smoke.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ 7-10 Days", startingPrice: "From ₹9,999", trustBadge: "SPCB Approved", targetUrl: "https://vrhere.in/pollution-noc"),
        ServiceItemModel(id: "factory-license", title: "Factory License & Plan Approval", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "gearshape.2.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 10-15 Days", startingPrice: "From ₹11,999", trustBadge: "Factories Act", targetUrl: "https://vrhere.in/factory-license"),
        ServiceItemModel(id: "fcra-registration", title: "FCRA Foreign Contribution Registration", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "globe.badge.chevron.backward", colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255), turnaround: "⚡ MHA Verified", startingPrice: "From ₹14,999", trustBadge: "Foreign Funding", targetUrl: "https://vrhere.in/fcra-registration"),
        ServiceItemModel(id: "ngo-darpan-registration", title: "NITI Aayog NGO DARPAN Portal", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "square.grid.3x3.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 24-48 Hours", startingPrice: "From ₹2,499", trustBadge: "Govt Grants", targetUrl: "https://vrhere.in/ngo-darpan-registration"),
        ServiceItemModel(id: "roc-annual-filings", title: "ROC Annual Filings (AOC-4, MGT-7)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "doc.badge.gearshape.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ Annual Filing", startingPrice: "From ₹4,999", trustBadge: "MCA21 V3", targetUrl: "https://vrhere.in/roc-annual-filings"),
        ServiceItemModel(id: "director-kyc", title: "Director KYC (DIR-3 KYC Online)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "person.crop.rectangle.badge.plus", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 10 Mins", startingPrice: "From ₹499", trustBadge: "Active DIN", targetUrl: "https://vrhere.in/director-kyc"),
        ServiceItemModel(id: "roc-search-certificate", title: "ROC Search Report & Title Search", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "magnifyingglass.circle.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹2,999", trustBadge: "Bank Ready", targetUrl: "https://vrhere.in/roc-search-certificate"),
        ServiceItemModel(id: "roc-charge-creation", title: "Charge Creation & Modification (CHG-1)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "link.circle.fill", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹3,999", trustBadge: "MCA Charge", targetUrl: "https://vrhere.in/roc-charge-creation"),
        ServiceItemModel(id: "change-in-shareholding", title: "Change in Shareholding & Transfer", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "person.2.badge.gearshape.fill", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹3,499", trustBadge: "SH-4 Stamped", targetUrl: "https://vrhere.in/change-in-shareholding"),
        ServiceItemModel(id: "change-in-directorship", title: "Change in Directorship (DIR-11/DIR-12)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "person.crop.circle.badge.checkmark", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹2,499", trustBadge: "MCA V3", targetUrl: "https://vrhere.in/change-in-directorship"),
        ServiceItemModel(id: "merger-demerger-winding-up", title: "Mergers, Demergers & Winding Up (STK-2)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "arrow.triangle.merge", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ NCLT / Fast Track", startingPrice: "From ₹24,999", trustBadge: "Legal Counsel", targetUrl: "https://vrhere.in/merger-demerger-winding-up"),
        ServiceItemModel(id: "bonus-loans-buyback", title: "Bonus Issue, Loan & Buyback Compliance", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "banknote.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹4,999", trustBadge: "MCA Filings", targetUrl: "https://vrhere.in/bonus-loans-buyback"),
        ServiceItemModel(id: "share-allotment-transfer", title: "Share Allotment (PAS-3) & Transfers", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "doc.on.doc.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 2-4 Days", startingPrice: "From ₹3,499", trustBadge: "Form PAS-3", targetUrl: "https://vrhere.in/share-allotment-transfer"),
        ServiceItemModel(id: "increase-share-capital", title: "Increase in Authorized Share Capital", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "chart.line.uptrend.xyaxis.circle.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹3,999", trustBadge: "SH-7 Approval", targetUrl: "https://vrhere.in/increase-share-capital"),
        ServiceItemModel(id: "company-name-address-change", title: "Change in Name, Address, Objects (INC-24)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "pencil.and.outline", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹3,499", trustBadge: "ROC Approval", targetUrl: "https://vrhere.in/company-name-address-change"),
        ServiceItemModel(id: "dsc-registration", title: "Class 3 Digital Signature (DSC + Token)", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "key.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 15 Mins", startingPrice: "From ₹1,499", trustBadge: "CCA India", targetUrl: "https://vrhere.in/dsc-registration"),
        ServiceItemModel(id: "rera-registration", title: "RERA Real Estate Agent / Project", categoryId: "LICENSE", categoryName: "Licensing & Govt", iconName: "house.and.flag.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹3,999", trustBadge: "State RERA", targetUrl: "https://vrhere.in/rera-registration"),

        // 5. MSME Schemes, Subsidies & Govt Portals (22)
        ServiceItemModel(id: "gem-registration", title: "GeM Govt Marketplace Primary Seller", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "cart.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹2,999", trustBadge: "Govt Tenders", targetUrl: "https://vrhere.in/gem-registration"),
        ServiceItemModel(id: "gem-oem-panel", title: "GeM OEM Panel & Brand Assessment", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "shield.lefthalf.filled", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹7,999", trustBadge: "OEM Verified", targetUrl: "https://vrhere.in/gem-oem-panel"),
        ServiceItemModel(id: "gem-brand-approval", title: "GeM Brand Approval & Catalog Creation", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "checkmark.seal.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹3,999", trustBadge: "Brand Approved", targetUrl: "https://vrhere.in/gem-brand-approval"),
        ServiceItemModel(id: "gem-product-listing", title: "GeM Product & Service Listing", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "list.bullet.rectangle.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹2,499", trustBadge: "Active Listing", targetUrl: "https://vrhere.in/gem-product-listing"),
        ServiceItemModel(id: "gem-tender-bidding", title: "GeM Bid Participation & Tender Mgmt", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "hammer.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ Real-time Bid", startingPrice: "From ₹9,999", trustBadge: "Tender Win Support", targetUrl: "https://vrhere.in/gem-tender-bidding"),
        ServiceItemModel(id: "treds-registration", title: "TReDS Invoice Factoring (RXIL, M1xchange)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "creditcard.circle.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 48 Hours", startingPrice: "From ₹3,499", trustBadge: "RBI Regulated", targetUrl: "https://vrhere.in/treds-registration"),
        ServiceItemModel(id: "single-window-registration", title: "State Single Window Clearances (AP/TS)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "window.casement.closed", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹4,999", trustBadge: "State DIC", targetUrl: "https://vrhere.in/single-window-registration"),
        ServiceItemModel(id: "npci-registration", title: "NPCI & BBPS Portal Onboarding", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "network", colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255), turnaround: "⚡ Fintech Sync", startingPrice: "From ₹9,999", trustBadge: "NPCI Approved", targetUrl: "https://vrhere.in/npci-registration"),
        ServiceItemModel(id: "ecommerce-seller-registration", title: "Amazon / Flipkart Seller Launch Kit", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "bag.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹2,499", trustBadge: "E-Commerce Ready", targetUrl: "https://vrhere.in/ecommerce-seller-registration"),
        ServiceItemModel(id: "dpr-cma-preparation", title: "Detailed Project Report (DPR Preparation)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "doc.text.image.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹4,999", trustBadge: "Bank Credit Ready", targetUrl: "https://vrhere.in/dpr-cma-preparation"),
        ServiceItemModel(id: "cma-data-preparation", title: "CMA Data Preparation for Bank Loans", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "chart.line.uptrend.xyaxis", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 48-72 Hours", startingPrice: "From ₹4,999", trustBadge: "CA Certified", targetUrl: "https://vrhere.in/cma-data-preparation"),
        ServiceItemModel(id: "bank-loans-support", title: "Term Loan & Working Capital Syndication", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "building.columns.circle.fill", colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255), turnaround: "⚡ Loan Sanction", startingPrice: "From ₹7,999", trustBadge: "Lowest Interest", targetUrl: "https://vrhere.in/bank-loans-support"),
        ServiceItemModel(id: "cgtmse-loan-support", title: "CGTMSE Collateral-Free Loans (Up to ₹5 Cr)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "shield.pattern.checkered", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ Bank Guarantee", startingPrice: "From ₹6,999", trustBadge: "Zero Collateral", targetUrl: "https://vrhere.in/cgtmse-loan-support"),
        ServiceItemModel(id: "pmegp-loan-support", title: "PMEGP Subsidy Loan (15% to 35% Subsidy)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "indianrupeesign.square.fill", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ KVIC / DIC Sync", startingPrice: "From ₹6,999", trustBadge: "35% Margin Money", targetUrl: "https://vrhere.in/pmegp-loan-support"),
        ServiceItemModel(id: "mudra-loans-support", title: "Mudra Loan Support (Shishu, Kishore, Tarun)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "banknote.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ Up to ₹10 Lakhs", startingPrice: "From ₹3,499", trustBadge: "Govt Scheme", targetUrl: "https://vrhere.in/mudra-loans-support"),
        ServiceItemModel(id: "standup-india-loans", title: "Stand-Up India Loan Support (SC/ST/Women)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "figure.stand", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ ₹10L - ₹1 Cr", startingPrice: "From ₹6,999", trustBadge: "Greenfield Unit", targetUrl: "https://vrhere.in/standup-india-loans"),
        ServiceItemModel(id: "zed-scheme-support", title: "MSME ZED Certification & CLCSS Subsidy", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "rosette", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ Bronze/Silver/Gold", startingPrice: "From ₹7,999", trustBadge: "Govt Subsidy", targetUrl: "https://vrhere.in/zed-scheme-support"),
        ServiceItemModel(id: "pmfme-subsidy-scheme", title: "PMFME Food Processing 35% Subsidy", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "cup.and.saucer.fill", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ MoFPI Scheme", startingPrice: "From ₹9,999", trustBadge: "₹10L Max Subsidy", targetUrl: "https://vrhere.in/pmfme-subsidy-scheme"),
        ServiceItemModel(id: "nsic-schemes-registration", title: "NSIC Single Point Registration (SPRS)", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "building.2.fill", colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹4,999", trustBadge: "Zero EMD Tenders", targetUrl: "https://vrhere.in/nsic-schemes-registration"),
        ServiceItemModel(id: "nabard-subsidy-schemes", title: "NABARD Agri-Infrastructure Subsidy", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "leaf.circle.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ Project Cycle", startingPrice: "From ₹11,999", trustBadge: "Agri Subsidy", targetUrl: "https://vrhere.in/nabard-subsidy-schemes"),
        ServiceItemModel(id: "cold-chain-subsidy", title: "Cold Chain & Value Addition Subsidies", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "snowflake", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ MoFPI Grant", startingPrice: "From ₹14,999", trustBadge: "Capital Grant", targetUrl: "https://vrhere.in/cold-chain-subsidy"),
        ServiceItemModel(id: "msme-subsidies-loans", title: "State Industrial Investment Subsidies", categoryId: "MSME", categoryName: "MSME & Schemes", iconName: "indianrupeesign.circle.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ State Incentives", startingPrice: "From ₹14,999", trustBadge: "Power & Stamp Duty", targetUrl: "https://vrhere.in/msme-subsidies-loans"),

        // 6. Branding & Industrial Setup (17)
        ServiceItemModel(id: "business-plan-preparation", title: "Investor-Grade Business Plan Drafting", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "doc.text.fill", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹7,999", trustBadge: "Investor Ready", targetUrl: "https://vrhere.in/business-plan-preparation"),
        ServiceItemModel(id: "pitch-deck-preparation", title: "VC & Angel Pitch Deck Design", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "play.rectangle.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹9,999", trustBadge: "Seed & Series A", targetUrl: "https://vrhere.in/pitch-deck-preparation"),
        ServiceItemModel(id: "website-branding-consulting", title: "Corporate Branding & Website Consulting", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "globe", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ Turnkey", startingPrice: "From ₹6,999", trustBadge: "Brand Identity", targetUrl: "https://vrhere.in/website-branding-consulting"),
        ServiceItemModel(id: "vendor-empanelment-docs", title: "Vendor Empanelment Documentation", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "folder.fill.badge.plus", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹4,999", trustBadge: "Corporate Onboarding", targetUrl: "https://vrhere.in/vendor-empanelment-docs"),
        ServiceItemModel(id: "hr-policy-documentation", title: "HR Policy Manual & Offer Letters", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "person.crop.artframe", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ 3-5 Days", startingPrice: "From ₹4,999", trustBadge: "Legal HR Handbooks", targetUrl: "https://vrhere.in/hr-policy-documentation"),
        ServiceItemModel(id: "sop-creation-services", title: "Standard Operating Procedures (SOPs)", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "checklist", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹6,999", trustBadge: "ISO Aligned", targetUrl: "https://vrhere.in/sop-creation-services"),
        ServiceItemModel(id: "loan-file-documentation", title: "Bank Loan File Processing & Liaison", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "tray.full.fill", colorTheme: Color(red: 100/255, green: 116/255, blue: 139/255), turnaround: "⚡ Banking Sync", startingPrice: "From ₹4,999", trustBadge: "Fast Sanctions", targetUrl: "https://vrhere.in/loan-file-documentation"),
        ServiceItemModel(id: "commercial-business-insurance", title: "Business, Fire & Marine Insurance", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "shield.lefthalf.filled", colorTheme: Color(red: 234/255, green: 88/255, blue: 12/255), turnaround: "⚡ 24 Hours", startingPrice: "From ₹2,999", trustBadge: "Risk Insured", targetUrl: "https://vrhere.in/commercial-business-insurance"),
        ServiceItemModel(id: "digital-marketing-support", title: "B2B Digital Marketing & Lead Gen", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "megaphone.fill", colorTheme: Color(red: 236/255, green: 72/255, blue: 153/255), turnaround: "⚡ Monthly Growth", startingPrice: "From ₹4,999/mo", trustBadge: "Verified Leads", targetUrl: "https://vrhere.in/digital-marketing-support"),
        ServiceItemModel(id: "pan-tan-applications", title: "PAN & TAN New / Correction Filing", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "creditcard.fill", colorTheme: Color(red: 59/255, green: 130/255, blue: 246/255), turnaround: "⚡ 24-48 Hours", startingPrice: "From ₹999", trustBadge: "NSDL / UTIITSL", targetUrl: "https://vrhere.in/pan-tan-applications"),
        ServiceItemModel(id: "trademark-registration", title: "Trademark Registration (TM & ®)", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "shield.righthalf.filled", colorTheme: Color(red: 99/255, green: 102/255, blue: 241/255), turnaround: "⚡ 24 Hours (TM)", startingPrice: "From ₹1,999", trustBadge: "IP India", targetUrl: "https://vrhere.in/trademark-registration"),
        ServiceItemModel(id: "wealth-portfolio-management", title: "Wealth & Corporate Treasury Advisory", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "chart.pie.fill", colorTheme: Color(red: 16/255, green: 185/255, blue: 129/255), turnaround: "⚡ Wealth Strategy", startingPrice: "From ₹9,999", trustBadge: "High Returns", targetUrl: "https://vrhere.in/wealth-portfolio-management"),
        ServiceItemModel(id: "machinery-sourcing", title: "Turnkey Industrial Machinery Sourcing", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "gearshape.fill", colorTheme: Color(red: 239/255, green: 68/255, blue: 68/255), turnaround: "⚡ Domestic & Import", startingPrice: "From ₹9,999", trustBadge: "OEM Vetted", targetUrl: "https://vrhere.in/machinery-sourcing"),
        ServiceItemModel(id: "vendor-verification-services", title: "Supplier Due Diligence & Verification", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "checkmark.shield.fill", colorTheme: Color(red: 14/255, green: 165/255, blue: 233/255), turnaround: "⚡ 2-3 Days", startingPrice: "From ₹4,999", trustBadge: "Zero Fraud Risk", targetUrl: "https://vrhere.in/vendor-verification-services"),
        ServiceItemModel(id: "turnkey-plant-engineering", title: "Turnkey Plant Setup & Engineering", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "building.2.crop.circle.fill", colorTheme: Color(red: 79/255, green: 70/255, blue: 229/255), turnaround: "⚡ Complete Setup", startingPrice: "From ₹19,999", trustBadge: "Plant Engineers", targetUrl: "https://vrhere.in/turnkey-plant-engineering"),
        ServiceItemModel(id: "technology-upgradation-consulting", title: "Technology Upgradation Consulting", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "cpu.fill", colorTheme: Color(red: 245/255, green: 158/255, blue: 11/255), turnaround: "⚡ Industry 4.0", startingPrice: "From ₹11,999", trustBadge: "Modernization", targetUrl: "https://vrhere.in/technology-upgradation-consulting"),
        ServiceItemModel(id: "industrial-feasibility-analysis", title: "Industrial Feasibility & Location Report", categoryId: "STARTUP", categoryName: "Industrial & Setup", iconName: "map.fill", colorTheme: Color(red: 168/255, green: 85/255, blue: 247/255), turnaround: "⚡ 5-7 Days", startingPrice: "From ₹14,999", trustBadge: "Full Feasibility", targetUrl: "https://vrhere.in/industrial-feasibility-analysis")
    ]
    
    private var filteredServices: [ServiceItemModel] {
        allServicesList.filter { item in
            let matchesCategory = selectedCategory == "ALL" || item.categoryId == selectedCategory
            let matchesSearch = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                item.title.localizedCaseInsensitiveContains(searchQuery) ||
                item.categoryName.localizedCaseInsensitiveContains(searchQuery)
            return matchesCategory && matchesSearch
        }
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // 1. Sleek Compact Header & Search
            VStack(spacing: 10) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Services Directory")
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("Choose a legal or compliance service to begin")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    Spacer()
                    
                    Text("\(filteredServices.count) Available")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                        .cornerRadius(12)
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
                
                // Creative Glowing Search Capsule
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(
                                LinearGradient(
                                    colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 79/255, green: 70/255, blue: 229/255)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 32, height: 32)
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.white)
                    }
                    
                    TextField("Search Company, GST, ISO, Licenses...", text: $searchQuery)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    
                    if !searchQuery.isEmpty {
                        Button(action: { searchQuery = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 16))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                    } else {
                        HStack(spacing: 3) {
                            Image(systemName: "sparkles")
                                .font(.system(size: 10, weight: .bold))
                            Text("Fast Find")
                                .font(.system(size: 9.5, weight: .black))
                        }
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                        .cornerRadius(8)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(
                            LinearGradient(
                                colors: [Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.4), Color(red: 14/255, green: 165/255, blue: 233/255).opacity(0.3)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 1.5
                        )
                )
                .shadow(color: Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.08), radius: 8, x: 0, y: 3)
                .padding(.horizontal, 16)
                
                // 2. Horizontal Category Filter Chips Bar
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(categoriesList, id: \.id) { cat in
                            let isSelected = selectedCategory == cat.id
                            Button(action: {
                                withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) {
                                    selectedCategory = cat.id
                                }
                                let impact = UIImpactFeedbackGenerator(style: .light)
                                impact.impactOccurred()
                            }) {
                                HStack(spacing: 5) {
                                    Image(systemName: cat.icon)
                                        .font(.system(size: 10, weight: .bold))
                                    Text(cat.name)
                                        .font(.system(size: 11, weight: isSelected ? .black : .bold))
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(
                                    isSelected
                                        ? Color(red: 15/255, green: 23/255, blue: 42/255)
                                        : Color.white
                                )
                                .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                .cornerRadius(14)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(isSelected ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                                .shadow(color: isSelected ? Color.black.opacity(0.12) : Color.clear, radius: 4, y: 2)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 2)
                }
            }
            .padding(.bottom, 6)
            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
            
            Divider()
                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
            
            // 3. Vibrant Services Cards List
            ScrollView(showsIndicators: false) {
                LazyVStack(spacing: 10) {
                    if filteredServices.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "doc.text.magnifyingglass")
                                .font(.system(size: 36))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                .padding(.top, 40)
                            Text("No matching services found")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                            Text("Try searching with different terms or reset your filters.")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        .padding(.horizontal, 20)
                    } else {
                        ForEach(filteredServices) { service in
                            Button(action: {
                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                let impact = UIImpactFeedbackGenerator(style: .medium)
                                impact.impactOccurred()
                                onOpenLiveService(service.title, service.targetUrl)
                            }) {
                                HStack(spacing: 12) {
                                    // Vibrant Icon Badge
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 14)
                                            .fill(service.colorTheme.opacity(0.12))
                                            .frame(width: 44, height: 44)
                                        Image(systemName: service.iconName)
                                            .font(.system(size: 18))
                                            .foregroundColor(service.colorTheme)
                                    }
                                    
                                    // Title & Highlights
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(service.title)
                                            .font(.system(size: 13.5, weight: .bold))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .lineLimit(1)
                                        
                                        HStack(spacing: 6) {
                                            Text(service.turnaround)
                                                .font(.system(size: 9.5, weight: .black))
                                                .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                                .cornerRadius(6)
                                            
                                            Text(service.trustBadge)
                                                .font(.system(size: 9.5, weight: .bold))
                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        }
                                    }
                                    
                                    Spacer()
                                    
                                    // Price & Arrow
                                    VStack(alignment: .trailing, spacing: 2) {
                                        Text(service.startingPrice)
                                            .font(.system(size: 11, weight: .black))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    }
                                }
                                .padding(12)
                                .background(Color.white)
                                .cornerRadius(16)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 2)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
                .padding(.bottom, 120) // extra bottom clearance so content scrolls cleanly above the dock
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }
}
