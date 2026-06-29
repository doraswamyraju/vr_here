import SwiftUI

struct AdminFinanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedType = "Invoice" // "Estimate" | "Invoice" | "Proforma" | "Payment" | "CreditNote"
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("FINANCE & TRANSACTION AUDIT")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Finance Ledger")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Manage estimates, proforma/sales invoices, payment receipts, and credit notes.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 10/255, green: 40/255, blue: 25/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Finance Type Selector
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach([
                            ("Estimate", "Estimates"),
                            ("Invoice", "Sale Invoices"),
                            ("Proforma", "Proforma"),
                            ("Payment", "Payments-In"),
                            ("CreditNote", "Credit Notes")
                        ], id: \.0) { typeKey, label in
                            Button(action: {
                                selectedType = typeKey
                                viewModel.fetchFinanceRecords(type: typeKey)
                            }) {
                                Text(label)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .foregroundColor(selectedType == typeKey ? .white : .textDark)
                                    .background(selectedType == typeKey ? Color.primaryRed : Color.bgInput)
                                    .cornerRadius(10)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Search bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search by document # or client...", text: $searchQuery)
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
                
                // Records list
                VStack(spacing: 12) {
                    let filtered = viewModel.financeRecords.filter {
                        searchQuery.isEmpty ||
                        $0.number.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.client.name.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    if filtered.isEmpty {
                        Text("No records found for \(selectedType)")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 30)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else {
                        ForEach(filtered) { record in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(record.number)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(record.client.name)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    VStack(alignment: .trailing, spacing: 4) {
                                        Text("₹\(Int(record.totals.total))")
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(.textDark)
                                        
                                        // Status badge
                                        Text(record.status.uppercased())
                                            .font(.system(size: 7, weight: .bold))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .foregroundColor(statusColor(record.status))
                                            .background(statusColor(record.status).opacity(0.12))
                                            .cornerRadius(4)
                                    }
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    Text("Date: \(record.date.prefix(10))")
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    if let due = record.dueDate {
                                        Text("Due: \(due.prefix(10))")
                                            .font(.system(size: 9))
                                            .foregroundColor(.textMuted)
                                    }
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
                
                Spacer().frame(height: 100)
            }
        }
        .onAppear {
            viewModel.fetchFinanceRecords(type: selectedType)
        }
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "paid", "accepted":
            return .green
        case "sent", "partially paid":
            return .blue
        case "draft", "pending":
            return .orange
        default:
            return .red
        }
    }
}
