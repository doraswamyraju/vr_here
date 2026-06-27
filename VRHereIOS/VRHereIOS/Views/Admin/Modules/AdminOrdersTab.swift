import SwiftUI

struct AdminOrdersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedOrderId = ""
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if selectedOrderId.isEmpty {
                    Text("All System Orders")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    TextField("Search client or service...", text: $searchQuery)
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(10)
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 12) {
                        let filtered = viewModel.orders.filter {
                            searchQuery.isEmpty ||
                            $0.serviceName.localizedCaseInsensitiveContains(searchQuery) ||
                            $0.clientName.localizedCaseInsensitiveContains(searchQuery)
                        }
                        
                        ForEach(filtered) { order in
                            Button(action: { selectedOrderId = order.id }) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(order.serviceName)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text("Client: \(order.clientName) • Price: ₹\(Int(order.price))")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    Text(order.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(order.status == "Completed" ? Color.green : Color.orange)
                                        .cornerRadius(6)
                                }
                                .glassCardStyle()
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 20)
                } else if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedOrderId = "" }) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.backward")
                                Text("Back to Orders")
                            }
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.red)
                        }
                        .padding(.top, 16)
                        
                        Text(order.serviceName)
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(.textDark)
                        
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Assignment & Workflow")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            
                            HStack {
                                Text("Client Name:")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(order.clientName)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                            
                            HStack {
                                Text("Assign Employee:")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(order.assignedEmployee?.name ?? "Unassigned")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.blue)
                            }
                            
                            Menu("Change Assignee") {
                                ForEach(viewModel.employees) { emp in
                                    Button(emp.name) {
                                        let fields: [String: AnyCodable] = ["assignedEmployee": AnyCodable(emp.idVal)]
                                        viewModel.createOrder(fields: fields) { _ in }
                                    }
                                }
                            }
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.red)
                        }
                        .glassCardStyle()
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
