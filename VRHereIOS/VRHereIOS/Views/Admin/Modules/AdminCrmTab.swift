import SwiftUI

struct AdminCrmTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var filterSelection = "Clients" // "Clients" or "Tickets"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("CUSTOMER RELATIONSHIP MANAGEMENT")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("CRM Central")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Track customer profiles, communications, and support requests.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 30/255, green: 20/255, blue: 55/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Segmented picker for Clients / Tickets
                HStack(spacing: 0) {
                    Button(action: { filterSelection = "Clients" }) {
                        Text("Clients Directory")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(filterSelection == "Clients" ? .white : .textMuted)
                            .frame(maxWidth: .infinity)
                            .frame(height: 36)
                            .background(filterSelection == "Clients" ? Color.primaryRed : Color.clear)
                            .cornerRadius(8)
                    }
                    Button(action: { filterSelection = "Tickets" }) {
                        Text("CRM Leads")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(filterSelection == "Tickets" ? .white : .textMuted)
                            .frame(maxWidth: .infinity)
                            .frame(height: 36)
                            .background(filterSelection == "Tickets" ? Color.primaryRed : Color.clear)
                            .cornerRadius(8)
                    }
                }
                .padding(4)
                .background(Color.bgInput)
                .cornerRadius(10)
                .padding(.horizontal, 20)
                
                // Search field
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search CRM database...", text: $searchQuery)
                        .font(.system(size: 13)       )
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // Content lists
                VStack(spacing: 12) {
                    if filterSelection == "Clients" {
                        // Extract unique clients dynamically from orders list
                        let uniqueClients = Dictionary(grouping: viewModel.orders, by: { $0.email }).values.compactMap { $0.first }
                        let filteredClients = uniqueClients.filter {
                            searchQuery.isEmpty ||
                            $0.clientName.localizedCaseInsensitiveContains(searchQuery) ||
                            $0.email.localizedCaseInsensitiveContains(searchQuery)
                        }
                        
                        if filteredClients.isEmpty {
                            Text("No client records in database")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                        } else {
                            ForEach(filteredClients) { client in
                                VStack(alignment: .leading, spacing: 8) {
                                    HStack {
                                        Text(client.clientName)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Spacer()
                                        
                                        // Count of service orders
                                        let count = viewModel.orders.filter { $0.email == client.email }.count
                                        Text("\(count) Orders")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.blue)
                                    }
                                    
                                    HStack {
                                        Text(client.email)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                        Spacer()
                                        Text(client.phone)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                }
                                .padding(16)
                                .background(Color.white)
                                .cornerRadius(16)
                                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                            }
                        }
                    } else {
                        // CRM Leads / Tickets list (Dynamic live integration)
                        let filteredTickets = viewModel.tickets.filter {
                            searchQuery.isEmpty ||
                            $0.subject.localizedCaseInsensitiveContains(searchQuery) ||
                            ($0.user?.name ?? "").localizedCaseInsensitiveContains(searchQuery)
                        }
                        
                        if filteredTickets.isEmpty {
                            Text("No CRM leads/tickets found")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(filteredTickets) { ticket in
                                HStack(spacing: 14) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(ticket.subject)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text("Account: \(ticket.user?.name ?? "Guest") • Priority: \(ticket.priority.capitalized)")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    Text(ticket.status.uppercased())
                                        .font(.system(size: 8, weight: .bold))
                                        .foregroundColor(ticket.status.lowercased() == "resolved" ? .green : (ticket.status.lowercased() == "pending" ? .orange : .red))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background((ticket.status.lowercased() == "resolved" ? Color.green : (ticket.status.lowercased() == "pending" ? Color.orange : Color.red)).opacity(0.12))
                                        .cornerRadius(6)
                                }
                                .padding(16)
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
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
