import SwiftUI

struct AdminRecurringTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("SUBSCRIPTION CONTRACTS & RENEWALS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Recurring Hub")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Audit auto-billing authorizations, active GST filings, and monthly compliance plans.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 10/255, blue: 40/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search by client or service name...", text: $searchQuery)
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
                
                // Recurring lists
                VStack(alignment: .leading, spacing: 14) {
                    Text("ACTIVE AUTO-BILLING AGREEMENTS")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    let filtered = viewModel.recurring.filter {
                        searchQuery.isEmpty ||
                        $0.serviceName.localizedCaseInsensitiveContains(searchQuery) ||
                        ($0.clientName ?? $0.user?.name ?? "").localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    VStack(spacing: 12) {
                        if filtered.isEmpty {
                            Text("No recurring services active")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(filtered) { sub in
                                VStack(alignment: .leading, spacing: 10) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(sub.serviceName)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text("Client: \(sub.clientName ?? sub.user?.name ?? "Guest") • Pack: \(sub.packageName)")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        
                                        // Status tag
                                        Text(sub.isActive ? "ACTIVE" : "PAUSED")
                                            .font(.system(size: 8, weight: .bold))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .foregroundColor(sub.isActive ? .green : .orange)
                                            .background((sub.isActive ? Color.green : Color.orange).opacity(0.12))
                                            .cornerRadius(6)
                                    }
                                    
                                    Divider().background(Color.borderLight)
                                    
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("Rate: ₹\(Int(sub.price)) • Freq: \(sub.frequency.capitalized)")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(.textDark.opacity(0.8))
                                            if !sub.nextRunDate.isEmpty {
                                                Text("Next Run: \(String(sub.nextRunDate.prefix(10)))")
                                                    .font(.system(size: 9))
                                                    .foregroundColor(.textMuted)
                                            }
                                        }
                                        
                                        Spacer()
                                        
                                        HStack(spacing: 12) {
                                            Button(action: {
                                                viewModel.toggleRecurringStatus(id: sub.idVal, isActive: !sub.isActive)
                                            }) {
                                                Image(systemName: sub.isActive ? "pause.circle.fill" : "play.circle.fill")
                                                    .font(.system(size: 18))
                                                    .foregroundColor(sub.isActive ? .orange : .green)
                                            }
                                            
                                            Button(action: {
                                                viewModel.deleteRecurring(id: sub.idVal)
                                            }) {
                                                Image(systemName: "trash.fill")
                                                    .font(.system(size: 16))
                                                    .foregroundColor(.red)
                                            }
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
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
