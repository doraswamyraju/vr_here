import SwiftUI

struct AdminComplianceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedCategory = "Dashboard"
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("REGULATORY AUDITS & DOCUMENTATION")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Compliance Panel")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Monitor GST returns, MCA filings, TDS status, and client tax updates.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 45/255, green: 30/255, blue: 15/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Category Filter Row
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach([
                            "Dashboard", "GST", "MCA", "DIN KYC", "TDS/TCS", "Income Tax", "Adv Tax", "ESI", "PF", "PT"
                        ], id: \.self) { category in
                            Button(action: { selectedCategory = category }) {
                                Text(category)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .foregroundColor(selectedCategory == category ? .white : .textDark)
                                    .background(selectedCategory == category ? Color.primaryRed : Color.bgInput)
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
                    TextField("Search client or task...", text: $searchQuery)
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
                
                // Compliance records list
                VStack(spacing: 12) {
                    let filtered = viewModel.complianceRecords.filter {
                        (selectedCategory == "Dashboard" || $0.category == selectedCategory) &&
                        (searchQuery.isEmpty ||
                         $0.clientName.localizedCaseInsensitiveContains(searchQuery) ||
                         $0.taskName.localizedCaseInsensitiveContains(searchQuery))
                    }
                    
                    if filtered.isEmpty {
                        Text("No compliance items found")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 30)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else {
                        ForEach(filtered) { item in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(item.taskName)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text("Client: \(item.clientName) • Month: \(item.periodMonth)")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    // Status Pill
                                    Text(item.status.uppercased())
                                        .font(.system(size: 8, weight: .bold))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(statusColor(item.status))
                                        .background(statusColor(item.status).opacity(0.12))
                                        .cornerRadius(6)
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    Text("Due Date: \(item.dueDate.prefix(10))")
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    
                                    // Update Action Menu
                                    Menu {
                                        ForEach(["Filed", "Late", "Missed", "Pending"], id: \.self) { status in
                                            Button(status.capitalized) {
                                                viewModel.updateComplianceStatus(id: item.idVal, status: status)
                                            }
                                        }
                                    } label: {
                                        Text("UPDATE STATUS")
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(.primaryRed)
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
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "filed":
            return .green
        case "pending":
            return .blue
        case "late":
            return .orange
        default:
            return .red
        }
    }
}
