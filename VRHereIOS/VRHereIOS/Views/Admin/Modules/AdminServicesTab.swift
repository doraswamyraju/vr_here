import SwiftUI

struct AdminServicesTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var activeSubTab: ServicesSubTab = .catalog
    @State private var tickerMessages: [String] = []
    @State private var capsules: [InteractiveCapsuleItem] = []
    @State private var servicesList: [ServiceHeaderConfigItem] = []
    @State private var isLoading: Bool = false
    @State private var isSaving: Bool = false
    @State private var newTickerText: String = ""
    @State private var newCapsuleLabel: String = ""
    @State private var newCapsuleLink: String = "/gst-registration"
    
    enum ServicesSubTab: String, CaseIterable {
        case catalog = "Services Master"
        case ticker = "Top Bar Ticker"
        case capsules = "Hero Capsules"
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("SERVICE CATALOG & HERO AUTOMATION • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Services Master")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        
                        Button(action: saveConfig) {
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
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                        }
                        .disabled(isSaving)
                    }
                    
                    Text("Manage header menu taxonomy, dynamic hero tags, latest promotional offers, and statutory package definitions.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 20/255, green: 20/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Sub-Tabs Switcher
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(ServicesSubTab.allCases, id: \.self) { tab in
                            let isSel = activeSubTab == tab
                            Button(action: { activeSubTab = tab }) {
                                Text(tab.rawValue)
                                    .font(.system(size: 12, weight: .bold))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .foregroundColor(isSel ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSel ? Color.indigoCustom : Color.white)
                                    .cornerRadius(12)
                                    .shadow(color: isSel ? Color.indigoCustom.opacity(0.3) : Color.clear, radius: 4, y: 2)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 12)
                                            .stroke(isSel ? Color.indigoCustom : Color.borderLight, lineWidth: 1)
                                    )
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Sub-Tab Content
                VStack {
                    if isLoading {
                        HStack {
                            Spacer()
                            ProgressView()
                            Spacer()
                        }
                        .padding(40)
                    } else {
                        switch activeSubTab {
                        case .catalog:
                            servicesCatalogView
                        case .ticker:
                            tickerView
                        case .capsules:
                            capsulesView
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            fetchConfig()
        }
    }
    
    // MARK: - Tab 1: Services Catalog
    private var servicesCatalogView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("CORPORATE SERVICE MODULES (\(ServiceCatalog.shared.items.count))")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            let catalogItems = ServiceCatalog.shared.items.values.sorted { $0.title < $1.title }
            ForEach(catalogItems, id: \.id) { serv in
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 12) {
                        Circle()
                            .fill(Color.primaryRed.opacity(0.12))
                            .frame(width: 36, height: 36)
                            .overlay(
                                Image(systemName: serv.iconKey)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.primaryRed)
                            )
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(serv.title)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(serv.description)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                                .lineLimit(2)
                        }
                        Spacer()
                    }
                    
                    Divider().background(Color.borderLight)
                    
                    // Packages Pills
                    HStack {
                        Text("\(serv.packages.count) Tiers Available")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.textDark)
                        Spacer()
                        if let minPrice = serv.packages.map({ $0.price }).min() {
                            Text("Starting at ₹\(Int(minPrice))")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.green)
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
    
    // MARK: - Tab 2: Ticker Messages
    private var tickerView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("TOP BAR TICKER (ANNOUNCEMENTS)")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            HStack(spacing: 8) {
                TextField("Add new announcement...", text: $newTickerText)
                    .font(.system(size: 12))
                    .padding(10)
                    .background(Color.white)
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                
                Button(action: {
                    if !newTickerText.trimmingCharacters(in: .whitespaces).isEmpty {
                        tickerMessages.append(newTickerText.trimmingCharacters(in: .whitespaces))
                        newTickerText = ""
                    }
                }) {
                    Text("Add")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(Color.indigoCustom)
                        .cornerRadius(10)
                }
            }
            
            if tickerMessages.isEmpty {
                Text("No announcements configured.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(20)
            } else {
                ForEach(Array(tickerMessages.enumerated()), id: \.offset) { idx, msg in
                    HStack {
                        Image(systemName: "megaphone.fill")
                            .font(.system(size: 12))
                            .foregroundColor(.indigoCustom)
                        Text(msg)
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { tickerMessages.remove(at: idx) }) {
                            Image(systemName: "trash")
                                .font(.system(size: 12))
                                .foregroundColor(.red)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Tab 3: Capsules
    private var capsulesView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("HERO SECTION CAPSULES (\(capsules.count)/10)")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
            }
            
            VStack(spacing: 8) {
                TextField("Capsule Tag Label (e.g. GST Filing)", text: $newCapsuleLabel)
                    .font(.system(size: 12))
                    .padding(10)
                    .background(Color.white)
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                
                HStack {
                    TextField("Target Link (e.g. /gst-registration)", text: $newCapsuleLink)
                        .font(.system(size: 12))
                        .padding(10)
                        .background(Color.white)
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                    
                    Button(action: {
                        if !newCapsuleLabel.isEmpty && capsules.count < 10 {
                            capsules.append(InteractiveCapsuleItem(text: newCapsuleLabel, link: newCapsuleLink))
                            newCapsuleLabel = ""
                        }
                    }) {
                        Text("Add Tag")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .background(Color.indigoCustom)
                            .cornerRadius(10)
                    }
                    .disabled(capsules.count >= 10 || newCapsuleLabel.isEmpty)
                }
            }
            
            ForEach(Array(capsules.enumerated()), id: \.offset) { idx, cap in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cap.text)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                        Text(cap.link ?? "/")
                            .font(.system(size: 10))
                            .foregroundColor(.textMuted)
                    }
                    Spacer()
                    Button(action: { capsules.remove(at: idx) }) {
                        Image(systemName: "trash")
                            .font(.system(size: 12))
                            .foregroundColor(.red)
                    }
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
            }
        }
    }
    
    // MARK: - API Calls
    private func fetchConfig() {
        isLoading = true
        Task {
            do {
                let res = try await NetworkManager.shared.getServicesHeaderConfig()
                tickerMessages = res.tickerMessages ?? []
                capsules = res.capsules ?? []
                servicesList = res.services ?? []
            } catch {
                print("Services header config load error: \(error)")
            }
            isLoading = false
        }
    }
    
    private func saveConfig() {
        isSaving = true
        Task {
            do {
                let payload: [String: AnyCodable] = [
                    "tickerMessages": AnyCodable(tickerMessages),
                    "capsules": AnyCodable(capsules.map { ["text": $0.text, "link": $0.link ?? ""] })
                ]
                _ = try await NetworkManager.shared.updateServicesHeaderConfig(payload: payload)
                viewModel.toastMessage = "Services configuration saved!"
            } catch {
                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
            }
            isSaving = false
        }
    }
}
