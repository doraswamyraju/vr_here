import SwiftUI

struct AdminRecurringTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var statusFilter: String = "All"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("RETAINERS & SUBSCRIPTIONS • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Recurring Hub")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Manage corporate retainer contracts, recurring GST compliance plans, auto-billing schedules, and active subscriptions.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 10/255, blue: 40/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search & Filter Bar
                VStack(spacing: 10) {
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.textMuted)
                        TextField("Search client or service name...", text: $searchQuery)
                            .font(.system(size: 12))
                        if !searchQuery.isEmpty {
                            Button(action: { searchQuery = "" }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.textMuted)
                            }
                        }
                    }
                    .padding(10)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                    
                    HStack(spacing: 8) {
                        ForEach(["All", "Active", "Paused"], id: \.self) { filter in
                            let isSel = statusFilter == filter
                            Button(action: { statusFilter = filter }) {
                                Text(filter)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .foregroundColor(isSel ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSel ? Color.indigoCustom : Color.white)
                                    .cornerRadius(8)
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(isSel ? Color.indigoCustom : Color.borderLight, lineWidth: 1))
                            }
                        }
                        Spacer()
                    }
                }
                .padding(.horizontal, 20)
                
                // Recurring Subscriptions List
                VStack(alignment: .leading, spacing: 14) {
                    let filtered = viewModel.recurring.filter { sub in
                        let matchesSearch = searchQuery.isEmpty ||
                            sub.serviceName.localizedCaseInsensitiveContains(searchQuery) ||
                            (sub.clientName ?? sub.user?.name ?? "").localizedCaseInsensitiveContains(searchQuery)
                        let matchesStatus = statusFilter == "All" ||
                            (statusFilter == "Active" && sub.isActive) ||
                            (statusFilter == "Paused" && !sub.isActive)
                        return matchesSearch && matchesStatus
                    }
                    
                    if filtered.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .font(.system(size: 32))
                                .foregroundColor(.textMuted)
                            Text("No recurring retainer agreements found.")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(40)
                        .background(Color.white)
                        .cornerRadius(16)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                    } else {
                        ForEach(filtered) { sub in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(sub.serviceName)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text("Client: \(sub.clientName ?? sub.user?.name ?? "Client") • Pack: \(sub.packageName)")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    Button(action: {
                                        viewModel.toggleRecurringStatus(id: sub.idVal, isActive: !sub.isActive)
                                    }) {
                                        Text(sub.isActive ? "ACTIVE" : "PAUSED")
                                            .font(.system(size: 8, weight: .black))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .foregroundColor(sub.isActive ? .green : .orange)
                                            .background((sub.isActive ? Color.green : Color.orange).opacity(0.12))
                                            .cornerRadius(6)
                                    }
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Rate: ₹\(Int(sub.price)) • Freq: \(sub.frequency.capitalized)")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.textDark)
                                        if !sub.nextRunDate.isEmpty {
                                            Text("Next Cycle: \(String(sub.nextRunDate.prefix(10)))")
                                                .font(.system(size: 9))
                                                .foregroundColor(.textMuted)
                                        }
                                    }
                                    
                                    Spacer()
                                    
                                    HStack(spacing: 8) {
                                        Button(action: {
                                            viewModel.deleteRecurring(id: sub.idVal)
                                        }) {
                                            Image(systemName: "trash")
                                                .font(.system(size: 12))
                                                .foregroundColor(.red)
                                                .padding(6)
                                                .background(Color.red.opacity(0.1))
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
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }
}
