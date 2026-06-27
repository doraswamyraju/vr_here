import SwiftUI

struct AdminCrmTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Support Ticket CRM Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                TextField("Search tickets...", text: $searchQuery)
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(10)
                    .padding(.horizontal, 20)
                
                VStack(spacing: 12) {
                    let leads = [
                        ("GST Issue", "Raju Ventures", "High", "Open"),
                        ("Filing Clarification", "Navya Enterprises", "Medium", "Pending"),
                        ("Incorporation Speedup", "Venkata Corp", "Low", "Resolved"),
                        ("Invoice Query", "Sai Logistics", "High", "Open")
                    ]
                    
                    ForEach(leads, id: \.0) { title, client, priority, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Client: \(client) • Priority: \(priority)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Resolved" ? Color.green : Color.red)
                                .cornerRadius(6)
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
