import SwiftUI

struct CustomerInvoicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Environment(\.openURL) private var openURL
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Bills & Payment Receipts")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.payments.isEmpty {
                    Text("No billing receipts found.")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.payments) { pay in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Text(pay.serviceName)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(pay.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(pay.status == "Completed" ? Color.green : Color.orange)
                                        .cornerRadius(6)
                                }
                                
                                Text(pay.packageName)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                HStack {
                                    Text("ID: \(pay.paymentId)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    Text("₹\(Int(pay.amount))")
                                        .font(.system(size: 14, weight: .black))
                                        .foregroundColor(.textDark)
                                }
                                
                                if let invUrl = pay.invoiceUrl, !invUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                    Divider().background(Color.borderLight)
                                    Button(action: {
                                        if let url = getAbsoluteURL(path: invUrl) {
                                            openURL(url)
                                        }
                                    }) {
                                        HStack {
                                            Image(systemName: "arrow.down.circle.fill")
                                                .foregroundColor(.blue)
                                            Text("Download Invoice PDF")
                                                .font(.system(size: 11, weight: .bold))
                                                .foregroundColor(.blue)
                                            Spacer()
                                        }
                                        .padding(.top, 4)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
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
