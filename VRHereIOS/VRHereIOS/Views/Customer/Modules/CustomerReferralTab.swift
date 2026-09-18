import SwiftUI

struct CustomerReferralTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    @State private var referralStats: CustomerReferralStatsResponse? = nil
    @State private var isLoading = true
    @State private var isCopied = false
    @State private var errorMessage: String? = nil
    
    // Add Friend Sheet
    @State private var showAddLeadSheet = false
    @State private var leadName = ""
    @State private var leadPhone = ""
    @State private var leadEmail = ""
    @State private var leadService = "Private Limited Company Registration"
    @State private var isSubmittingLead = false
    
    // UPI Payout Sheet
    @State private var showPayoutSheet = false
    @State private var upiId = ""
    @State private var payoutAmount = ""
    @State private var isSubmittingPayout = false
    
    // Alert / Toast
    @State private var alertTitle = ""
    @State private var alertMessage = ""
    @State private var showAlert = false
    
    @Environment(\.openURL) private var openURL
    
    let serviceOptions = [
        "Private Limited Company Registration",
        "GST Registration & Filings",
        "LLP Registration",
        "Trademark Registration",
        "Income Tax Return & Assessment",
        "Bookkeeping & AaaS Package",
        "FSSAI Food License",
        "Import Export Code (IEC)",
        "ISO Certification"
    ]
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(spacing: 20) {
                // Header Banner
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 24)
                        .fill(
                            LinearGradient(
                                colors: [Color(hex: "991B1B"), Color(hex: "DC2626"), Color(hex: "EA580C")],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                    
                    VStack(alignment: .leading, spacing: 14) {
                        HStack {
                            Label("REFER & EARN CASH", systemImage: "gift.fill")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.yellow)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(Color.black.opacity(0.3))
                                .cornerRadius(8)
                            
                            Spacer()
                            
                            Text("₹500 / Referral")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(Color.white.opacity(0.2))
                                .cornerRadius(12)
                        }
                        
                        Text("Earn ₹500 for every business friend who incorporates or files taxes with us")
                            .font(.system(size: 18, weight: .bold))
                            .foregroundColor(.white)
                            .lineLimit(3)
                        
                        // Referral Code & Share Card
                        VStack(spacing: 10) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("YOUR EXCLUSIVE CODE")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.white.opacity(0.8))
                                    Text(referralStats?.referralCode.isEmpty == false ? (referralStats?.referralCode ?? "...") : "GENERATING...")
                                        .font(.system(size: 18, weight: .black, design: .monospaced))
                                        .foregroundColor(.white)
                                }
                                
                                Spacer()
                                
                                Button(action: copyReferralLink) {
                                    HStack(spacing: 6) {
                                        Image(systemName: isCopied ? "checkmark" : "doc.on.doc.fill")
                                        Text(isCopied ? "COPIED" : "COPY LINK")
                                    }
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(Color(hex: "991B1B"))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 10)
                                    .background(Color.white)
                                    .cornerRadius(12)
                                    .shadow(color: Color.black.opacity(0.15), radius: 4, y: 2)
                                }
                            }
                            
                            // WhatsApp Share Button
                            Button(action: shareViaWhatsApp) {
                                HStack {
                                    Image(systemName: "message.fill")
                                    Text("Share on WhatsApp Instantly")
                                }
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .background(Color(hex: "16A34A"))
                                .cornerRadius(12)
                                .shadow(color: Color.green.opacity(0.3), radius: 4, y: 2)
                            }
                        }
                        .padding(14)
                        .background(Color.black.opacity(0.2))
                        .cornerRadius(16)
                    }
                    .padding(20)
                }
                .padding(.horizontal)
                .padding(.top, 10)
                
                // Stats Grid
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    // Total Invited
                    StatCard(
                        title: "TOTAL INVITED",
                        value: "\(referralStats?.totalInvited ?? 0)",
                        icon: "person.2.fill",
                        color: Color.blue
                    )
                    
                    // Successful Conversions
                    StatCard(
                        title: "CONVERTED",
                        value: "\(referralStats?.successfulConversions ?? 0)",
                        icon: "checkmark.seal.fill",
                        color: Color.green
                    )
                    
                    // Total Earned
                    StatCard(
                        title: "TOTAL EARNED",
                        value: "₹\(Int(referralStats?.totalEarned ?? 0))",
                        icon: "indianrupeesign.circle.fill",
                        color: Color.purple
                    )
                    
                    // Wallet Balance
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: "wallet.pass.fill")
                                .font(.system(size: 14))
                                .foregroundColor(Color.orange)
                            Spacer()
                            if (referralStats?.walletBalance ?? 0) >= 500 {
                                Button(action: { showPayoutSheet = true }) {
                                    Text("WITHDRAW")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(Color.orange)
                                        .cornerRadius(6)
                                }
                            }
                        }
                        
                        Text("AVAILABLE WALLET")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(.secondary)
                        
                        Text("₹\(Int(referralStats?.walletBalance ?? 0))")
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(.primary)
                    }
                    .padding(14)
                    .background(Color(uiColor: .secondarySystemGroupedBackground))
                    .cornerRadius(16)
                    .shadow(color: Color.black.opacity(0.04), radius: 6, y: 2)
                }
                .padding(.horizontal)
                
                // Direct Referral Action Button
                Button(action: { showAddLeadSheet = true }) {
                    HStack {
                        Image(systemName: "plus.circle.fill")
                        Text("Refer a Friend Directly (Submit Contact)")
                    }
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(Color(hex: "0F172A"))
                    .cornerRadius(16)
                    .shadow(color: Color.black.opacity(0.1), radius: 6, y: 3)
                }
                .padding(.horizontal)
                
                // Referral History Section
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("REFERRAL ACTIVITY")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.secondary)
                        
                        Spacer()
                        
                        Button(action: loadStats) {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.red)
                        }
                    }
                    .padding(.horizontal)
                    
                    if isLoading {
                        HStack {
                            Spacer()
                            ProgressView()
                            Spacer()
                        }
                        .padding(.vertical, 30)
                    } else if let list = referralStats?.referrals, !list.isEmpty {
                        VStack(spacing: 10) {
                            ForEach(list) { ref in
                                ReferralItemRow(item: ref)
                            }
                        }
                        .padding(.horizontal)
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "gift")
                                .font(.system(size: 36))
                                .foregroundColor(.gray.opacity(0.5))
                            Text("No referrals yet")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.secondary)
                            Text("Share your referral link with business contacts to start earning ₹500 rewards.")
                                .font(.system(size: 12))
                                .foregroundColor(.gray)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 20)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 30)
                        .background(Color(uiColor: .secondarySystemGroupedBackground))
                        .cornerRadius(16)
                        .padding(.horizontal)
                    }
                }
                .padding(.top, 8)
                
                Spacer(minLength: 60)
            }
        }
        .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        .onAppear(perform: loadStats)
        .sheet(isPresented: $showAddLeadSheet) {
            AddLeadSheetView(
                leadName: $leadName,
                leadPhone: $leadPhone,
                leadEmail: $leadEmail,
                leadService: $leadService,
                isSubmitting: isSubmittingLead,
                serviceOptions: serviceOptions,
                onSubmit: submitAddLead,
                onDismiss: { showAddLeadSheet = false }
            )
        }
        .sheet(isPresented: $showPayoutSheet) {
            PayoutSheetView(
                walletBalance: referralStats?.walletBalance ?? 0,
                upiId: $upiId,
                amount: $payoutAmount,
                isSubmitting: isSubmittingPayout,
                onSubmit: submitPayout,
                onDismiss: { showPayoutSheet = false }
            )
        }
        .alert(isPresented: $showAlert) {
            Alert(title: Text(alertTitle), message: Text(alertMessage), dismissButton: .default(Text("OK")))
        }
    }
    
    private func loadStats() {
        isLoading = true
        Task {
            do {
                let stats = try await NetworkManager.shared.getCustomerReferralStats()
                self.referralStats = stats
                if let saved = stats.savedUpiId, !saved.isEmpty {
                    self.upiId = saved
                }
                self.isLoading = false
            } catch {
                self.errorMessage = error.localizedDescription
                self.isLoading = false
            }
        }
    }
    
    private func copyReferralLink() {
        guard let link = referralStats?.referralLink, !link.isEmpty else { return }
        UIPasteboard.general.string = link
        isCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            isCopied = false
        }
    }
    
    private func shareViaWhatsApp() {
        guard let code = referralStats?.referralCode, let link = referralStats?.referralLink else { return }
        let text = "Hey! I use VR Here for company registrations, GST, and CA compliances. You can get your business registered or file taxes with their expert CA team.\n\nUse my referral link for priority onboarding: \(link) (or code: \(code))"
        guard let encoded = text.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "https://api.whatsapp.com/send?text=\(encoded)") else { return }
        openURL(url)
    }
    
    private func submitAddLead() {
        guard !leadName.trimmingCharacters(in: .whitespaces).isEmpty else {
            alertTitle = "Required"
            alertMessage = "Please enter contact name."
            showAlert = true
            return
        }
        let cleanPhone = leadPhone.filter { $0.isNumber }
        guard cleanPhone.count >= 10 else {
            alertTitle = "Invalid Phone"
            alertMessage = "Please enter a valid 10-digit mobile number."
            showAlert = true
            return
        }
        
        isSubmittingLead = true
        Task {
            do {
                let res = try await NetworkManager.shared.addCustomerReferralLead(
                    name: leadName,
                    phone: cleanPhone,
                    email: leadEmail.isEmpty ? nil : leadEmail,
                    interestedService: leadService
                )
                isSubmittingLead = false
                showAddLeadSheet = false
                leadName = ""
                leadPhone = ""
                leadEmail = ""
                alertTitle = "Success"
                alertMessage = res.message ?? "Referral added successfully! You will receive ₹500 reward once completed."
                showAlert = true
                loadStats()
            } catch {
                isSubmittingLead = false
                alertTitle = "Error"
                alertMessage = error.localizedDescription
                showAlert = true
            }
        }
    }
    
    private func submitPayout() {
        guard upiId.contains("@") else {
            alertTitle = "Invalid UPI"
            alertMessage = "Please enter a valid UPI ID (e.g. name@okhdfcbank)."
            showAlert = true
            return
        }
        let amt = Double(payoutAmount) ?? (referralStats?.walletBalance ?? 0)
        guard amt >= 500 else {
            alertTitle = "Minimum Amount"
            alertMessage = "Minimum payout withdrawal is ₹500."
            showAlert = true
            return
        }
        
        isSubmittingPayout = true
        Task {
            do {
                let res = try await NetworkManager.shared.requestCustomerUpiPayout(amount: amt, upiId: upiId)
                isSubmittingPayout = false
                showPayoutSheet = false
                payoutAmount = ""
                alertTitle = "Payout Requested"
                alertMessage = res.message ?? "Your UPI payout request of ₹\(Int(amt)) has been submitted."
                showAlert = true
                loadStats()
            } catch {
                isSubmittingPayout = false
                alertTitle = "Payout Failed"
                alertMessage = error.localizedDescription
                showAlert = true
            }
        }
    }
}

// MARK: - Subcomponents

private struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(color)
            
            Text(title)
                .font(.system(size: 10, weight: .black))
                .foregroundColor(.secondary)
            
            Text(value)
                .font(.system(size: 20, weight: .black))
                .foregroundColor(.primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.04), radius: 6, y: 2)
    }
}

private struct ReferralItemRow: View {
    let item: CustomerReferralItem
    
    var statusColor: Color {
        switch item.status.lowercased() {
        case "rewarded", "converted": return Color.green
        case "order_placed": return Color.blue
        case "registered": return Color.orange
        default: return Color.gray
        }
    }
    
    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(statusColor.opacity(0.15))
                .frame(width: 40, height: 40)
                .overlay(
                    Image(systemName: item.status.lowercased() == "rewarded" ? "checkmark.circle.fill" : "person.fill")
                        .foregroundColor(statusColor)
                )
            
            VStack(alignment: .leading, spacing: 3) {
                Text(item.refereeName)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.primary)
                
                Text(item.interestedService ?? "Registration & Compliance")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            
            Spacer()
            
            VStack(alignment: .trailing, spacing: 4) {
                Text(item.status.uppercased())
                    .font(.system(size: 9, weight: .black))
                    .foregroundColor(statusColor)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(statusColor.opacity(0.12))
                    .cornerRadius(6)
                
                if item.status.lowercased() == "rewarded" {
                    Text("+₹\(Int(item.rewardAmount ?? 500))")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.green)
                }
            }
        }
        .padding(12)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .cornerRadius(14)
        .shadow(color: Color.black.opacity(0.03), radius: 4, y: 1)
    }
}

private struct AddLeadSheetView: View {
    @Binding var leadName: String
    @Binding var leadPhone: String
    @Binding var leadEmail: String
    @Binding var leadService: String
    let isSubmitting: Bool
    let serviceOptions: [String]
    let onSubmit: () -> Void
    let onDismiss: () -> Void
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Friend / Client Details")) {
                    TextField("Full Name (e.g. Rahul Sharma)", text: $leadName)
                    TextField("10-Digit Mobile Number", text: $leadPhone)
                        .keyboardType(.phonePad)
                    TextField("Email Address (Optional)", text: $leadEmail)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                }
                
                Section(header: Text("Interested Service")) {
                    Picker("Service Required", selection: $leadService) {
                        ForEach(serviceOptions, id: \.self) { opt in
                            Text(opt).tag(opt)
                        }
                    }
                }
                
                Section {
                    Button(action: onSubmit) {
                        if isSubmitting {
                            HStack {
                                Spacer()
                                ProgressView()
                                Spacer()
                            }
                        } else {
                            Text("Submit Referral & Track")
                                .font(.system(size: 15, weight: .bold))
                                .frame(maxWidth: .infinity, alignment: .center)
                                .foregroundColor(.red)
                        }
                    }
                    .disabled(isSubmitting)
                }
            }
            .navigationTitle("Refer a Friend")
            .navigationBarItems(leading: Button("Cancel", action: onDismiss))
        }
    }
}

private struct PayoutSheetView: View {
    let walletBalance: Double
    @Binding var upiId: String
    @Binding var amount: String
    let isSubmitting: Bool
    let onSubmit: () -> Void
    let onDismiss: () -> Void
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Wallet Status")) {
                    HStack {
                        Text("Available for Withdrawal")
                        Spacer()
                        Text("₹\(Int(walletBalance))")
                            .font(.system(size: 16, weight: .black))
                            .foregroundColor(.green)
                    }
                }
                
                Section(header: Text("UPI Details")) {
                    TextField("UPI ID (e.g. mobile@upi)", text: $upiId)
                        .autocapitalization(.none)
                        .autocorrectionDisabled()
                    
                    TextField("Amount (Min ₹500)", text: $amount)
                        .keyboardType(.numberPad)
                }
                
                Section {
                    Button(action: onSubmit) {
                        if isSubmitting {
                            HStack {
                                Spacer()
                                ProgressView()
                                Spacer()
                            }
                        } else {
                            Text("Request Payout Transfer")
                                .font(.system(size: 15, weight: .bold))
                                .frame(maxWidth: .infinity, alignment: .center)
                                .foregroundColor(.green)
                        }
                    }
                    .disabled(isSubmitting)
                }
            }
            .navigationTitle("Request UPI Payout")
            .navigationBarItems(leading: Button("Cancel", action: onDismiss))
        }
    }
}
