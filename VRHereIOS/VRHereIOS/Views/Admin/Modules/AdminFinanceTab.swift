import SwiftUI

struct AdminFinanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Finance Ledger")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("Total Operations Pipeline Value")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    Text("₹\(Int(viewModel.totalPipelineValue))")
                        .font(.system(size: 26, weight: .black))
                        .foregroundColor(.green)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                Text("Transactions Status")
                    .font(.system(size: 14, weight: .bold))
                    .padding(.horizontal, 20)
                
                if viewModel.payments.isEmpty {
                    Text("No transactions logged.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    ForEach(viewModel.payments) { pay in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Order #\(pay.paymentId.prefix(8))")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Mode: \(pay.method) • Status: \(pay.status)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("₹\(Int(pay.amount))")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.green)
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
