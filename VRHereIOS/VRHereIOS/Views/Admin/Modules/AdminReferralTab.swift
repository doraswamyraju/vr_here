import SwiftUI

struct AdminReferralTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var activeSubTab: ReferralSubTab = .partners
    @State private var searchQuery: String = ""
    @State private var payoutSearchQuery: String = ""
    @State private var payouts: [PartnerAdminPayoutItem] = []
    @State private var isLoadingPayouts: Bool = false
    
    // Partner Drilldown state
    @State private var selectedPartner: UserResponse? = nil
    @State private var editingPartner: UserResponse? = nil
    
    // Payout modal state
    @State private var selectedPayoutToProcess: PartnerAdminPayoutItem? = nil
    
    enum ReferralSubTab: String, CaseIterable {
        case partners = "Partners Directory"
        case payouts = "Payout Requests"
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("AFFILIATES & CHANNEL PARTNERS • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Referral Hub")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        
                        Button(action: {
                            viewModel.syncDashboardData()
                            fetchPayouts()
                        }) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .padding(10)
                                .background(Color.white.opacity(0.15))
                                .cornerRadius(10)
                        }
                    }
                    
                    Text("Control commission rates, audit referral conversions, review bank/UPI accounts, and process payout requests.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 10/255, green: 25/255, blue: 40/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // If in Partner Drilldown mode
                if let partner = selectedPartner {
                    partnerDetailView(partner: partner)
                        .padding(.horizontal, 20)
                } else {
                    // Sub-Tabs Switcher
                    HStack(spacing: 8) {
                        ForEach(ReferralSubTab.allCases, id: \.self) { tab in
                            let isSel = activeSubTab == tab
                            Button(action: { activeSubTab = tab }) {
                                HStack(spacing: 4) {
                                    Text(tab.rawValue)
                                    if tab == .payouts {
                                        let pending = payouts.filter { $0.status.lowercased() == "pending" }.count
                                        if pending > 0 {
                                            Text("\(pending)")
                                                .font(.system(size: 9, weight: .black))
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(Color.red)
                                                .foregroundColor(.white)
                                                .cornerRadius(6)
                                        }
                                    }
                                }
                                .font(.system(size: 12, weight: .bold))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 8)
                                .foregroundColor(isSel ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                .background(isSel ? Color.indigoCustom : Color.white)
                                .cornerRadius(12)
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(isSel ? Color.indigoCustom : Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    
                    // Main Sub-Tab Content
                    VStack {
                        if activeSubTab == .partners {
                            partnersDirectoryView
                        } else {
                            payoutsView
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            fetchPayouts()
        }
        .sheet(item: $editingPartner) { partner in
            EditPartnerSheet(partner: partner) { updated in
                viewModel.syncDashboardData()
            }
        }
        .sheet(item: $selectedPayoutToProcess) { payout in
            ProcessPayoutSheet(payout: payout) {
                fetchPayouts()
            }
        }
    }
    
    // MARK: - Tab 1: Partners Directory
    private var partnersDirectoryView: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Search Bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.textMuted)
                TextField("Search by partner name, phone, email, PAN...", text: $searchQuery)
                    .font(.system(size: 12))
            }
            .padding(10)
            .background(Color.white)
            .cornerRadius(12)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
            
            let partners = viewModel.users.filter { $0.role.lowercased() == "partner" }
            let filtered = partners.filter {
                searchQuery.isEmpty ||
                $0.name.localizedCaseInsensitiveContains(searchQuery) ||
                $0.email.localizedCaseInsensitiveContains(searchQuery) ||
                ($0.phone ?? "").localizedCaseInsensitiveContains(searchQuery) ||
                ($0.panCard ?? "").localizedCaseInsensitiveContains(searchQuery)
            }
            
            if filtered.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "person.2.slash")
                        .font(.system(size: 32))
                        .foregroundColor(.textMuted)
                    Text("No referral partners found matching search")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(40)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
            } else {
                ForEach(filtered) { partner in
                    let partnerOrders = viewModel.orders.filter { $0.referralPartner == partner.idVal }
                    let totalVolume = partnerOrders.reduce(0.0) { $0 + $1.price }
                    let totalEarned = partnerOrders.reduce(0.0) { $0 + ($1.partnerCommissionAmount ?? 0.0) }
                    
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Circle()
                                .fill(Color.indigoCustom.opacity(0.12))
                                .frame(width: 38, height: 38)
                                .overlay(
                                    Text(String(partner.name.prefix(1)).uppercased())
                                        .font(.system(size: 14, weight: .black))
                                        .foregroundColor(.indigoCustom)
                                )
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(partner.name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                HStack(spacing: 6) {
                                    if let p = partner.phone {
                                        Text(p).font(.system(size: 10)).foregroundColor(.textMuted)
                                    }
                                    if let pan = partner.panCard {
                                        Text("PAN: \(pan)").font(.system(size: 9, weight: .bold)).foregroundColor(.indigoCustom)
                                    }
                                }
                            }
                            
                            Spacer()
                            
                            Button(action: {
                                viewModel.toggleUserActive(id: partner.idVal)
                            }) {
                                Text(partner.isActive ? "ACTIVE" : "PAUSED")
                                    .font(.system(size: 8, weight: .black))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .foregroundColor(partner.isActive ? .green : .orange)
                                    .background((partner.isActive ? Color.green : Color.orange).opacity(0.12))
                                    .cornerRadius(6)
                            }
                        }
                        
                        Divider().background(Color.borderLight)
                        
                        HStack {
                            VStack(alignment: .leading, spacing: 1) {
                                Text("Rate")
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(.textMuted)
                                Text("\(Int(partner.commissionPercentage ?? 10))%")
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(.primaryRed)
                            }
                            Spacer()
                            VStack(alignment: .leading, spacing: 1) {
                                Text("Referred Vol")
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(.textMuted)
                                Text("₹\(Int(totalVolume))")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                            Spacer()
                            VStack(alignment: .leading, spacing: 1) {
                                Text("Earned")
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(.textMuted)
                                Text("₹\(Int(totalEarned))")
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(.green)
                            }
                            Spacer()
                            
                            HStack(spacing: 6) {
                                Button(action: { selectedPartner = partner }) {
                                    Image(systemName: "eye.fill")
                                        .font(.system(size: 12))
                                        .foregroundColor(.indigoCustom)
                                        .padding(6)
                                        .background(Color.indigoCustom.opacity(0.1))
                                        .cornerRadius(6)
                                }
                                
                                Button(action: { editingPartner = partner }) {
                                    Image(systemName: "pencil")
                                        .font(.system(size: 12))
                                        .foregroundColor(.textDark)
                                        .padding(6)
                                        .background(Color.bgInput)
                                        .cornerRadius(6)
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
    }
    
    // MARK: - Tab 2: Payout Requests
    private var payoutsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Payout Search Bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.textMuted)
                TextField("Search by partner, phone, UPI, UTR...", text: $payoutSearchQuery)
                    .font(.system(size: 12))
            }
            .padding(10)
            .background(Color.white)
            .cornerRadius(12)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
            
            if isLoadingPayouts {
                HStack {
                    Spacer()
                    ProgressView()
                    Spacer()
                }
                .padding(40)
            } else {
                let filtered = payouts.filter { p in
                    payoutSearchQuery.isEmpty ||
                    (p.partner?.name ?? "").localizedCaseInsensitiveContains(payoutSearchQuery) ||
                    (p.upiId ?? "").localizedCaseInsensitiveContains(payoutSearchQuery) ||
                    (p.transactionRef ?? "").localizedCaseInsensitiveContains(payoutSearchQuery)
                }
                
                if filtered.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "creditcard")
                            .font(.system(size: 32))
                            .foregroundColor(.textMuted)
                        Text("No payout requests recorded.")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(40)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                } else {
                    ForEach(filtered) { p in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(p.partner?.name ?? "Partner")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(p.payoutMethod == "UPI" ? "UPI: \(p.upiId ?? "-")" : "Bank A/C: \(p.bankDetails?.accountNumber ?? "-")")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                VStack(alignment: .trailing, spacing: 2) {
                                    Text("₹\(Int(p.amount))")
                                        .font(.system(size: 14, weight: .black))
                                        .foregroundColor(.textDark)
                                    Text(p.status.uppercased())
                                        .font(.system(size: 8, weight: .black))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 3)
                                        .foregroundColor(payoutStatusColor(p.status))
                                        .background(payoutStatusColor(p.status).opacity(0.12))
                                        .cornerRadius(4)
                                }
                            }
                            
                            if let ref = p.transactionRef, !ref.isEmpty {
                                Text("UTR / Ref: \(ref)")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                            
                            Divider().background(Color.borderLight)
                            
                            HStack {
                                Text(p.createdAt.prefix(10))
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Button(action: {
                                    selectedPayoutToProcess = p
                                }) {
                                    Text("Process / Update")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 6)
                                        .background(Color.indigoCustom)
                                        .cornerRadius(8)
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
        }
    }
    
    // MARK: - Partner Drilldown Orders Ledger View
    private func partnerDetailView(partner: UserResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Button(action: { selectedPartner = nil }) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.backward")
                    Text("Back to Partner List")
                }
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.indigoCustom)
            }
            .padding(.top, 10)
            
            VStack(alignment: .leading, spacing: 6) {
                Text(partner.name)
                    .font(.system(size: 20, weight: .black))
                    .foregroundColor(.white)
                HStack(spacing: 12) {
                    Text(partner.email)
                        .font(.system(size: 11))
                        .foregroundColor(.white.opacity(0.8))
                    if let pan = partner.panCard {
                        Text("PAN: \(pan)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.cyan)
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.darkSlate)
            .cornerRadius(18)
            
            Text("REFERRED BUSINESS LEDGER")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            let orders = viewModel.orders.filter { $0.referralPartner == partner.idVal }
            if orders.isEmpty {
                Text("No orders referred yet by this partner.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(20)
            } else {
                ForEach(orders) { ord in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(ord.serviceName)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Client: \(ord.clientName)")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("₹\(Int(ord.price))")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.textDark)
                                Text("Commission: ₹\(Int(ord.partnerCommissionAmount ?? 0))")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.green)
                            }
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
    
    private func fetchPayouts() {
        isLoadingPayouts = true
        Task {
            do {
                payouts = try await NetworkManager.shared.getPartnerAdminPayouts()
            } catch {
                print("Payouts load error: \(error)")
            }
            isLoadingPayouts = false
        }
    }
    
    private func payoutStatusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "paid": return .green
        case "approved": return .blue
        case "rejected": return .red
        default: return .orange
        }
    }
}

// MARK: - Process Payout Sheet
struct ProcessPayoutSheet: View {
    let payout: PartnerAdminPayoutItem
    let onProcessed: () -> Void
    
    @Environment(\.presentationMode) var presentationMode
    @State private var status: String = "Paid"
    @State private var transactionRef: String = ""
    @State private var adminNotes: String = ""
    @State private var isSubmitting: Bool = false
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("PAYOUT DETAILS").font(.system(size: 10, weight: .black))) {
                    HStack {
                        Text("Partner:")
                        Spacer()
                        Text(payout.partner?.name ?? "-").bold()
                    }
                    HStack {
                        Text("Amount:")
                        Spacer()
                        Text("₹\(Int(payout.amount))").bold().foregroundColor(.green)
                    }
                    HStack {
                        Text("Method:")
                        Spacer()
                        Text(payout.payoutMethod)
                    }
                }
                
                Section(header: Text("DECISION & UTR DETAILS").font(.system(size: 10, weight: .black))) {
                    Picker("Status", selection: $status) {
                        ForEach(["Paid", "Approved", "Rejected"], id: \.self) { st in
                            Text(st).tag(st)
                        }
                    }
                    
                    TextField("Bank UTR / Transaction Ref", text: $transactionRef)
                        .font(.system(size: 13))
                    
                    TextField("Admin Notes / Remarks", text: $adminNotes)
                        .font(.system(size: 13))
                }
            }
            .navigationTitle("Process Payout")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { presentationMode.wrappedValue.dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Commit") {
                        isSubmitting = true
                        Task {
                            do {
                                let payload: [String: AnyCodable] = [
                                    "status": AnyCodable(status),
                                    "transactionRef": AnyCodable(transactionRef),
                                    "adminNotes": AnyCodable(adminNotes)
                                ]
                                _ = try await NetworkManager.shared.updatePartnerAdminPayout(id: payout.idVal, payload: payload)
                                onProcessed()
                                presentationMode.wrappedValue.dismiss()
                            } catch {
                                print("Error processing payout: \(error)")
                            }
                            isSubmitting = false
                        }
                    }
                    .font(.system(size: 13, weight: .black))
                    .disabled(isSubmitting)
                }
            }
            .onAppear {
                status = payout.status == "Pending" ? "Paid" : payout.status
                transactionRef = payout.transactionRef ?? ""
                adminNotes = payout.adminNotes ?? ""
            }
        }
    }
}

// MARK: - Edit Partner Sheet
struct EditPartnerSheet: View {
    let partner: UserResponse
    let onSaved: (UserResponse) -> Void
    
    @Environment(\.presentationMode) var presentationMode
    @State private var name: String = ""
    @State private var email: String = ""
    @State private var phone: String = ""
    @State private var panCard: String = ""
    @State private var commissionPercentage: String = "10"
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("PARTNER IDENTITY").font(.system(size: 10, weight: .black))) {
                    TextField("Partner Name", text: $name).font(.system(size: 13))
                    TextField("Email Address", text: $email).font(.system(size: 13))
                    TextField("Phone", text: $phone).font(.system(size: 13))
                    TextField("PAN Card", text: $panCard).font(.system(size: 13))
                }
                
                Section(header: Text("COMMISSION TERMS").font(.system(size: 10, weight: .black))) {
                    TextField("Default Commission %", text: $commissionPercentage)
                        .font(.system(size: 13))
                        .keyboardType(.numberPad)
                }
            }
            .navigationTitle("Edit Partner")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { presentationMode.wrappedValue.dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") {
                        Task {
                            do {
                                let payload: [String: AnyCodable] = [
                                    "name": AnyCodable(name),
                                    "email": AnyCodable(email),
                                    "phone": AnyCodable(phone),
                                    "panCard": AnyCodable(panCard),
                                    "commissionPercentage": AnyCodable(Double(commissionPercentage) ?? 10.0)
                                ]
                                let bodyData = try JSONEncoder().encode(payload)
                                let updated: UserResponse = try await NetworkManager.shared.performRequest(path: "api/auth/users/\(partner.idVal)", method: "PUT", body: bodyData)
                                onSaved(updated)
                                presentationMode.wrappedValue.dismiss()
                            } catch {
                                print("Error updating partner: \(error)")
                            }
                        }
                    }
                    .font(.system(size: 13, weight: .black))
                }
            }
            .onAppear {
                name = partner.name
                email = partner.email
                phone = partner.phone ?? ""
                panCard = partner.panCard ?? ""
                commissionPercentage = "\(Int(partner.commissionPercentage ?? 10))"
            }
        }
    }
}
