import SwiftUI

struct AdminOrdersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if viewModel.selectedOrderId.isEmpty {
                    // Header console card
                    VStack(alignment: .leading, spacing: 8) {
                        Text("ALL SYSTEM ORDERS")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(.cyan)
                            .tracking(1)
                        Text("Service Pipeline")
                            .font(.system(size: 24, weight: .black))
                            .foregroundColor(.white)
                        Text("Manage service assignments, status tracking, and delivery timelines.")
                            .font(.system(size: 12))
                            .foregroundColor(.white.opacity(0.7))
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 35/255, blue: 60/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .cornerRadius(20)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                    
                    // Search bar
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.textMuted)
                        TextField("Search client or service...", text: $searchQuery)
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
                    
                    // Filter Chips Bar
                    let filterOptions = ["All", "Pending", "Completed", "Pending Documents", "Documents Verified", "In Progress"]
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(filterOptions, id: \.self) { opt in
                                let isSelected = viewModel.selectedOrderFilter.lowercased() == opt.lowercased()
                                Button(action: {
                                    withAnimation {
                                        viewModel.selectedOrderFilter = opt
                                    }
                                }) {
                                    Text(opt)
                                        .font(.system(size: 11, weight: .bold))
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 6)
                                        .foregroundColor(isSelected ? .white : .textDark)
                                        .background(isSelected ? Color.primaryRed : Color.white)
                                        .cornerRadius(20)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 20)
                                                .stroke(isSelected ? Color.primaryRed : Color.borderLight, lineWidth: 1)
                                        )
                                }
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                    
                    // Orders list
                    VStack(spacing: 12) {
                        let filtered = viewModel.orders.filter { order in
                            let matchesSearch = searchQuery.isEmpty ||
                                order.serviceName.localizedCaseInsensitiveContains(searchQuery) ||
                                order.clientName.localizedCaseInsensitiveContains(searchQuery)
                            
                            let matchesStatus: Bool
                            let f = viewModel.selectedOrderFilter.lowercased()
                            if f == "all" {
                                matchesStatus = true
                            } else if f == "pending" {
                                matchesStatus = order.status.lowercased() != "completed"
                            } else if f == "completed" {
                                matchesStatus = order.status.lowercased() == "completed"
                            } else {
                                matchesStatus = order.status.localizedCaseInsensitiveContains(viewModel.selectedOrderFilter)
                            }
                            
                            return matchesSearch && matchesStatus
                        }
                        
                        if filtered.isEmpty {
                            Text("No matching orders found")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                        } else {
                            ForEach(filtered) { order in
                                Button(action: { viewModel.selectedOrderId = order.id }) {
                                    HStack(spacing: 14) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(order.serviceName)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                                .multilineTextAlignment(.leading)
                                            Text("Client: \(order.clientName) • Price: ₹\(Int(order.price))")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        
                                        // Status badge
                                        Text(order.status.uppercased())
                                            .font(.system(size: 8, weight: .bold))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .foregroundColor(statusColor(order.status))
                                            .background(statusColor(order.status).opacity(0.12))
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
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    
                } else if let order = viewModel.orders.first(where: { $0.id == viewModel.selectedOrderId }) {
                    // Detail Screen
                    VStack(alignment: .leading, spacing: 20) {
                        Button(action: { viewModel.selectedOrderId = "" }) {
                            HStack(spacing: 6) {
                                Image(systemName: "chevron.backward")
                                Text("Back to Orders")
                             }
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.primaryRed)
                        }
                        .padding(.top, 16)
                        
                        Text(order.serviceName)
                            .font(.system(size: 22, weight: .black))
                            .foregroundColor(.textDark)
                        
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Assignment & Workflow")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.textDark)
                            
                            detailRow(title: "Client Name:", value: order.clientName)
                            detailRow(title: "Client Email:", value: order.email)
                            detailRow(title: "Price Value:", value: "₹\(Int(order.price))")
                            detailRow(title: "Payment ID:", value: order.paymentId.isEmpty ? "None" : order.paymentId)
                            
                            Divider().background(Color.borderLight)
                            
                            HStack {
                                Text("Assignee:")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(order.assignedEmployee?.name ?? "Unassigned")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(order.assignedEmployee != nil ? .blue : .orange)
                            }
                            
                            // Reassign menu
                            Menu {
                                ForEach(viewModel.employees) { emp in
                                    Button(emp.name) {
                                        let fields: [String: AnyCodable] = ["assignedEmployee": AnyCodable(emp.idVal)]
                                        viewModel.createOrder(fields: fields) { _ in }
                                    }
                                }
                            } label: {
                                HStack {
                                    Image(systemName: "person.badge.plus")
                                    Text("Change Assignee")
                                }
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 38)
                                .background(Color.primaryRed)
                                .cornerRadius(8)
                            }
                        }
                        .padding(18)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 4)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
    
    private func detailRow(title: String, value: String) -> some View {
        HStack {
            Text(title)
                .font(.system(size: 12))
                .foregroundColor(.textMuted)
            Spacer()
            Text(value)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.textDark)
        }
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "completed":
            return .green
        case "in progress", "processing":
            return .blue
        case "pending":
            return .orange
        default:
            return .red
        }
    }
}
