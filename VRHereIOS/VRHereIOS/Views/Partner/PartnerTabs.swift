import SwiftUI

// ==========================================
// 1. PARTNER OVERVIEW TAB
// ==========================================
struct PartnerOverviewTab: View {
    @ObservedObject var viewModel: PartnerDashboardViewModel
    let userName: String
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 4) {
                    Text("Partner Overview")
                        .font(.system(size: 22, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Welcome back, \(userName). Track your commissions.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Analytics cards
                let totalEarnings = viewModel.orders.reduce(0.0) { $0 + $1.partnerCommissionAmount }
                let pendingCount = viewModel.orders.filter { $0.status != "Completed" }.count
                
                VStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Total Commission Earned")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                        Text("₹\(Int(totalEarnings))")
                            .font(.system(size: 28, weight: .black))
                            .foregroundColor(.purple)
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.purple.opacity(0.1))
                    .cornerRadius(16)
                    
                    HStack(spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Total Referrals")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.orders.count)")
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Active Trackings")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(pendingCount)")
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 2. PARTNER REFERRALS TAB
// ==========================================
struct PartnerReferralsTab: View {
    @ObservedObject var viewModel: PartnerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Your Client Referrals")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.orders.isEmpty {
                    Text("No clients referred yet.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.orders) { ref in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(ref.clientName)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(ref.serviceName)
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Text(ref.status)
                                    .font(.system(size: 9, weight: .bold))
                                    .foregroundColor(.purple)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Color.purple.opacity(0.1))
                                    .cornerRadius(6)
                            }
                            .padding(14)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 3. PARTNER EARNINGS TAB
// ==========================================
struct PartnerEarningsTab: View {
    @ObservedObject var viewModel: PartnerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Referrals Commission Earnings")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                let completedPayouts = viewModel.orders.filter { $0.partnerCommissionAmount > 0 }
                
                if completedPayouts.isEmpty {
                    Text("No earnings settlements calculated yet.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(completedPayouts) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.clientName)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text("Referred: \(item.createdAt)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Text("₹\(Int(item.partnerCommissionAmount))")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.green)
                            }
                            .padding(12)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 4. PARTNER BANK SETTINGS TAB
// ==========================================
struct PartnerSettingsTab: View {
    @ObservedObject var viewModel: PartnerDashboardViewModel
    let onDeleteAccount: () -> Void
    
    @State private var showingDeleteAlert = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Partner Configuration Settings")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 16) {
                    CustomInputField(label: "Full Registered Name", placeholder: "Name", iconName: "person", text: $viewModel.nameInput)
                    CustomInputField(label: "PAN Card number (verification)", placeholder: "PAN Card", iconName: "creditcard", text: $viewModel.panCardInput)
                    
                    Divider().background(Color.borderLight)
                    
                    Text("Commission Bank Settlement Details")
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.textDark)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    CustomInputField(label: "Account Holder Name", placeholder: "Holder name", iconName: "person.text.rectangle", text: $viewModel.bankAccountNameInput)
                    CustomInputField(label: "Bank Account Number", placeholder: "Account number", iconName: "number", text: $viewModel.bankAccountNumberInput)
                    CustomInputField(label: "IFSC Code", placeholder: "IFSC Code", iconName: "building.columns", text: $viewModel.bankIfscCodeInput)
                    CustomInputField(label: "Bank Name", placeholder: "E.g. HDFC Bank", iconName: "building", text: $viewModel.bankNameInput)
                    
                    Button(action: {
                        viewModel.updateProfile()
                    }) {
                        HStack {
                            if viewModel.isSavingProfile {
                                ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Image(systemName: "checkmark")
                                Text("UPDATE DETAILS")
                            }
                        }
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 44)
                        .background(Color.purple)
                        .cornerRadius(10)
                    }
                    .disabled(viewModel.isSavingProfile)
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                // Danger Zone
                VStack(alignment: .leading, spacing: 12) {
                    Text("Danger Zone")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.primaryRed)
                    
                    Text("Permanently delete your partner account and all associated commission tracking. This action is irreversible.")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                        .lineLimit(nil)
                    
                    Button(action: {
                        showingDeleteAlert = true
                    }) {
                        Text("Delete Account")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .alert(isPresented: $showingDeleteAlert) {
            Alert(
                title: Text("Delete Account?"),
                message: Text("Are you sure you want to permanently delete your partner account? All your commission history will be destroyed immediately. This cannot be undone."),
                primaryButton: .destructive(Text("Delete Permanently")) {
                    onDeleteAccount()
                },
                secondaryButton: .cancel()
            )
        }
    }
}
