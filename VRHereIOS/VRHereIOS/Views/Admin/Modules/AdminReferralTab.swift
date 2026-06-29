import SwiftUI

struct AdminReferralTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("PARTNER CHANNELS & PROMOTIONS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Referral Ledger")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Monitor affiliate payouts, referral codes, and partner commissions.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 10/255, green: 25/255, blue: 40/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search partner by name or email...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // Referrals statistics card
                VStack(alignment: .leading, spacing: 14) {
                    Text("PARTNER SUMMARY")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    let partners = viewModel.users.filter { $0.role.lowercased() == "partner" }
                    let filteredPartners = partners.filter {
                        searchQuery.isEmpty ||
                        $0.name.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.email.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    VStack(spacing: 12) {
                        if filteredPartners.isEmpty {
                            Text("No referral partners registered")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(filteredPartners) { partner in
                                // Calculate conversions and earnings dynamically
                                let partnerOrders = viewModel.orders.filter { $0.referralPartner == partner.idVal }
                                let signupsCount = partnerOrders.count
                                let totalRevenue = partnerOrders.reduce(0.0) { $0 + $1.price }
                                let totalCommission = partnerOrders.reduce(0.0) { $0 + ($1.partnerCommissionAmount ?? 0.0) }
                                
                                VStack(alignment: .leading, spacing: 8) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(partner.name)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text("Email: \(partner.email) • Rate: \(Int(partner.commissionPercentage ?? 10))%")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        
                                        // Earnings Tag
                                        Text("₹\(Int(totalCommission)) Earned")
                                            .font(.system(size: 10, weight: .bold))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .foregroundColor(.green)
                                            .background(Color.green.opacity(0.12))
                                            .cornerRadius(6)
                                    }
                                    
                                    Divider().background(Color.borderLight)
                                    
                                    HStack {
                                        Text("Conversions: \(signupsCount) orders")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Spacer()
                                        Text("Referred Volume: ₹\(Int(totalRevenue))")
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                    }
                                }
                                .padding(14)
                                .background(Color.white)
                                .cornerRadius(16)
                                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
