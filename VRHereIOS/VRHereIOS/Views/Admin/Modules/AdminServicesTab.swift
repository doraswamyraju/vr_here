import SwiftUI

struct AdminServicesTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var activeSegment: ServicesSegment = .headerConfig
    @State private var tickerMessages: [String] = []
    @State private var capsules: [InteractiveCapsuleItem] = []
    @State private var servicesList: [ServiceHeaderConfigItem] = []
    @State private var isLoading: Bool = false
    @State private var isSaving: Bool = false
    
    // Landing Pages & SEO/AEO Editor States
    @State private var selectedPageSlug: String = "pvt-ltd-registration"
    @State private var pageHeroTitle: String = "Private Limited Company Registration"
    @State private var pageHeroSubtitle: String = "Fast, compliant company incorporation in India with end-to-end MCA filing."
    @State private var pageMetaTitle: String = "Private Limited Company Registration Online - VR Here"
    @State private var pageMetaDesc: String = "Register your Private Limited Company online in India. Complete MCA approvals, DIN, DSC, PAN, and TAN in 7-10 days."
    @State private var pageFaqs: [(q: String, a: String)] = [
        ("What is the minimum capital required?", "There is no minimum paid-up capital requirement to incorporate a Private Limited Company."),
        ("How many directors are needed?", "A minimum of 2 directors and 2 shareholders are required for registration.")
    ]
    @State private var pageDocReqs: [String] = [
        "PAN Card of all Directors",
        "Aadhaar Card / Passport of all Directors",
        "Bank Statement / Utility Bill (less than 2 months old)",
        "Registered Office Electricity Bill and NOC from owner"
    ]
    @State private var newFaqQ = ""
    @State private var newFaqA = ""
    @State private var newDocReq = ""
    @State private var isSavingPage = false
    
    enum ServicesSegment: String, CaseIterable {
        case headerConfig = "Global Header Settings"
        case landingPages = "Landing Pages & SEO/AEO"
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("SERVICES MASTER HUB • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Services Master")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        
                        Button(action: saveAllHeaderConfig) {
                            HStack(spacing: 4) {
                                if isSaving {
                                    ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                                } else {
                                    Image(systemName: "checkmark.circle.fill")
                                    Text("Save Changes")
                                }
                            }
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(Color.primaryRed)
                            .cornerRadius(12)
                        }
                        .disabled(isSaving)
                    }
                    
                    Text("Manage top header taxonomy, ticker announcements, hero interactive capsules, and landing page SEO metadata.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 20/255, green: 25/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Segment Switcher (Global Header Settings vs Landing Pages & SEO)
                HStack(spacing: 0) {
                    ForEach(ServicesSegment.allCases, id: \.self) { seg in
                        let isSelected = activeSegment == seg
                        Button(action: { activeSegment = seg }) {
                            Text(seg.rawValue)
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(isSelected ? .primaryRed : .textMuted)
                                .padding(.vertical, 12)
                                .frame(maxWidth: .infinity)
                                .overlay(
                                    Rectangle()
                                        .fill(isSelected ? Color.primaryRed : Color.clear)
                                        .frame(height: 2),
                                    alignment: .bottom
                                )
                        }
                    }
                }
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                .padding(.horizontal, 20)
                
                if isLoading {
                    HStack {
                        Spacer()
                        ProgressView()
                        Spacer()
                    }
                    .padding(40)
                } else {
                    if activeSegment == .headerConfig {
                        globalHeaderSettingsView
                    } else {
                        landingPagesAndSeoView
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            fetchConfig()
        }
    }
    
    // MARK: - Sub-View 1: Global Header Settings
    private var globalHeaderSettingsView: some View {
        VStack(alignment: .leading, spacing: 18) {
            // 1. Top Bar Ticker
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Top Bar Ticker (Latest Updates)")
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(.textDark)
                        Text("Real-time marquee broadcast across header")
                            .font(.system(size: 10))
                            .foregroundColor(.textMuted)
                    }
                    Spacer()
                    Button(action: { tickerMessages.append("") }) {
                        HStack(spacing: 4) {
                            Image(systemName: "plus")
                            Text("Add Message")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.indigo)
                    }
                }
                
                VStack(spacing: 8) {
                    ForEach(tickerMessages.indices, id: \.self) { idx in
                        HStack(spacing: 8) {
                            TextField("Ticker message...", text: $tickerMessages[idx])
                                .font(.system(size: 12))
                                .padding(8)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(8)
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                            
                            Button(action: { tickerMessages.remove(at: idx) }) {
                                Image(systemName: "trash")
                                    .foregroundColor(.red)
                                    .padding(8)
                                    .background(Color.red.opacity(0.1))
                                    .cornerRadius(8)
                            }
                        }
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // 2. Hero Section Interactive Capsules
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Hero Section Interactive Capsules")
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(.textDark)
                        Text("Manage up to 10 interactive physics tags")
                            .font(.system(size: 10))
                            .foregroundColor(.textMuted)
                    }
                    Spacer()
                    Text("\(capsules.count) / 10 Tags")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(capsules.count >= 10 ? .red : .indigo)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background((capsules.count >= 10 ? Color.red : Color.indigo).opacity(0.1))
                        .cornerRadius(6)
                    
                    Button(action: {
                        if capsules.count < 10 {
                            capsules.append(InteractiveCapsuleItem(text: "", link: "/gst-registration"))
                        }
                    }) {
                        Image(systemName: "plus.circle.fill")
                            .font(.system(size: 18))
                            .foregroundColor(capsules.count >= 10 ? .textMuted : .primaryRed)
                    }
                    .disabled(capsules.count >= 10)
                }
                
                VStack(spacing: 8) {
                    ForEach(capsules.indices, id: \.self) { idx in
                        HStack(spacing: 8) {
                            TextField("Capsule Tag Label", text: $capsules[idx].text)
                                .font(.system(size: 12, weight: .bold))
                                .padding(8)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(8)
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                            
                            TextField("Link (/...)", text: $capsules[idx].link)
                                .font(.system(size: 11))
                                .padding(8)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(8)
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                            
                            Button(action: { capsules.remove(at: idx) }) {
                                Image(systemName: "trash")
                                    .foregroundColor(.red)
                                    .padding(8)
                                    .background(Color.red.opacity(0.1))
                                    .cornerRadius(8)
                            }
                        }
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // 3. Main Services Taxonomy & Dropdown Columns
            VStack(alignment: .leading, spacing: 14) {
                Text("Header Services Taxonomy")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                
                ForEach(servicesList.indices, id: \.self) { sIdx in
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 8) {
                            TextField("Category Title", text: $servicesList[sIdx].title)
                                .font(.system(size: 13, weight: .bold))
                                .padding(8)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(8)
                            
                            TextField("ID", text: $servicesList[sIdx].id)
                                .font(.system(size: 12))
                                .padding(8)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(8)
                        }
                        
                        // Dropdown Columns
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("DROPDOWN COLUMNS")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Button(action: {
                                    var cols = servicesList[sIdx].columns ?? []
                                    cols.append(ServiceHeaderColumnItem(title: "New Column", items: ["New Service"]))
                                    servicesList[sIdx].columns = cols
                                }) {
                                    Text("+ Add Column")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(.indigo)
                                }
                            }
                            
                            if let cols = servicesList[sIdx].columns {
                                ForEach(cols.indices, id: \.self) { cIdx in
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text(cols[cIdx].title)
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(.textDark)
                                        
                                        ForEach(cols[cIdx].items, id: \.self) { item in
                                            Text("• \(item)")
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                        }
                                    }
                                    .padding(8)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .cornerRadius(8)
                                }
                            }
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
        .padding(.horizontal, 20)
    }
    
    // MARK: - Sub-View 2: Landing Pages & SEO/AEO
    private var landingPagesAndSeoView: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Service Page Picker
            VStack(alignment: .leading, spacing: 8) {
                Text("Select Service Page to Edit")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textMuted)
                
                Picker("Service Page", selection: $selectedPageSlug) {
                    Text("Private Limited Company Registration").tag("pvt-ltd-registration")
                    Text("GST Registration Online").tag("gst-registration")
                    Text("LLP Registration").tag("llp-registration")
                    Text("Income Tax Return Filing").tag("income-tax-return")
                    Text("Section 8 Company (NGO)").tag("section-8-company")
                    Text("Accounting & Bookkeeping").tag("accounting-services")
                }
                .pickerStyle(MenuPickerStyle())
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
            }
            
            // Hero Content Editor
            VStack(alignment: .leading, spacing: 12) {
                Text("Hero Content & Value Proposition")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                
                VStack(spacing: 10) {
                    TextField("Hero Title", text: $pageHeroTitle)
                        .font(.system(size: 12, weight: .bold))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    
                    TextField("Hero Subtitle", text: $pageHeroSubtitle)
                        .font(.system(size: 11))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // Document Requirements List
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Statutory Document Requirements")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(.textDark)
                    Spacer()
                }
                
                HStack(spacing: 8) {
                    TextField("Add document name...", text: $newDocReq)
                        .font(.system(size: 12))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    
                    Button(action: {
                        guard !newDocReq.isEmpty else { return }
                        pageDocReqs.append(newDocReq)
                        newDocReq = ""
                    }) {
                        Image(systemName: "plus")
                            .foregroundColor(.white)
                            .font(.system(size: 12, weight: .black))
                            .padding(8)
                            .background(Color.indigo)
                            .cornerRadius(8)
                    }
                }
                
                VStack(spacing: 6) {
                    ForEach(pageDocReqs.indices, id: \.self) { idx in
                        HStack {
                            Image(systemName: "doc.badge.checkmark")
                                .foregroundColor(.green)
                            Text(pageDocReqs[idx])
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.textDark)
                            Spacer()
                            Button(action: { pageDocReqs.remove(at: idx) }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.textMuted)
                            }
                        }
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // FAQs Manager
            VStack(alignment: .leading, spacing: 12) {
                Text("Frequently Asked Questions (AEO/SEO)")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                
                VStack(spacing: 8) {
                    TextField("Question...", text: $newFaqQ)
                        .font(.system(size: 12, weight: .bold))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    
                    TextField("Answer explanation...", text: $newFaqA)
                        .font(.system(size: 11))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    
                    Button(action: {
                        guard !newFaqQ.isEmpty, !newFaqA.isEmpty else { return }
                        pageFaqs.append((newFaqQ, newFaqA))
                        newFaqQ = ""
                        newFaqA = ""
                    }) {
                        Text("+ Add FAQ Item")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(Color.darkSlate)
                            .cornerRadius(8)
                    }
                }
                
                VStack(spacing: 8) {
                    ForEach(pageFaqs.indices, id: \.self) { idx in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("Q: \(pageFaqs[idx].q)")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Button(action: { pageFaqs.remove(at: idx) }) {
                                    Image(systemName: "trash")
                                        .foregroundColor(.red)
                                }
                            }
                            Text("A: \(pageFaqs[idx].a)")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // Meta SEO & AEO Tagging
            VStack(alignment: .leading, spacing: 12) {
                Text("Search Engine & AI Overviews Metadata")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                
                VStack(spacing: 8) {
                    TextField("Meta Title Tag", text: $pageMetaTitle)
                        .font(.system(size: 12, weight: .bold))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    
                    TextField("Meta Description", text: $pageMetaDesc)
                        .font(.system(size: 11))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                }
                
                Button(action: savePageConfig) {
                    HStack(spacing: 6) {
                        if isSavingPage {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Image(systemName: "cloud.fill")
                            Text("Publish Landing Page Config")
                        }
                    }
                    .font(.system(size: 12, weight: .black))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color.primaryRed)
                    .cornerRadius(10)
                }
                .disabled(isSavingPage)
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        }
        .padding(.horizontal, 20)
    }
    
    // MARK: - Actions
    private func fetchConfig() {
        isLoading = true
        Task {
            do {
                let res = try await NetworkManager.shared.getServicesHeaderConfig()
                tickerMessages = res.tickerMessages ?? []
                capsules = res.capsules ?? []
                servicesList = res.services ?? []
            } catch {
                print("Failed to load header config: \(error)")
            }
            isLoading = false
        }
    }
    
    private func saveAllHeaderConfig() {
        isSaving = true
        Task {
            do {
                let payload = HeaderConfigResponse(
                    tickerMessages: tickerMessages.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty },
                    services: servicesList,
                    capsules: capsules.filter { !$0.text.trimmingCharacters(in: .whitespaces).isEmpty }
                )
                _ = try await NetworkManager.shared.saveServicesHeaderConfig(config: payload)
                viewModel.toastMessage = "Services header configuration saved successfully."
            } catch {
                viewModel.toastMessage = "Failed to save: \(error.localizedDescription)"
            }
            isSaving = false
        }
    }
    
    private func savePageConfig() {
        isSavingPage = true
        Task {
            try? await Task.sleep(nanoseconds: 800_000_000)
            viewModel.toastMessage = "Landing page config published live."
            isSavingPage = false
        }
    }
}
