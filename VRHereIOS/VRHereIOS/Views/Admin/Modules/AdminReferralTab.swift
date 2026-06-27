import SwiftUI

struct AdminReferralTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Referral Commission Ledger")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let referrals = [
                        ("Pranav Kumar", "Referred 3 clients", "₹3,500 Paid"),
                        ("Nisha Reddy", "Referred 1 client", "₹1,000 Pending"),
                        ("Kiran Dev", "Referred 5 clients", "₹6,000 Paid")
                    ]
                    
                    ForEach(referrals, id: \.0) { partner, desc, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(partner)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(desc)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(status.contains("Paid") ? .green : .orange)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
