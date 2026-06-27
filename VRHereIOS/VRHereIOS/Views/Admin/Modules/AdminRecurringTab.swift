import SwiftUI

struct AdminRecurringTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Recurring Subscriptions")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let plans = [
                        ("Monthly Retainer Compliance", "₹15,000/mo", "4 Active Clients"),
                        ("Quarterly TDS Filing Pack", "₹6,500/quarter", "11 Active Clients"),
                        ("Yearly Business Compliance Suite", "₹45,000/year", "8 Active Clients")
                    ]
                    
                    ForEach(plans, id: \.0) { name, rate, stats in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text(name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Text(rate)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.blue)
                            }
                            Text(stats)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
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
