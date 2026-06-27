import SwiftUI

struct AdminFreelancersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Freelancer Hub Management")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                TextField("Search freelancers...", text: $searchQuery)
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(10)
                    .padding(.horizontal, 20)
                
                VStack(spacing: 12) {
                    let filtered = viewModel.freelancers.filter {
                        searchQuery.isEmpty ||
                        $0.name.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.email.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    if filtered.isEmpty {
                        Text("No active freelancers found.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        ForEach(filtered) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.name)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text("Role: \(item.role.capitalized) • \(item.email)")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                            }
                            .glassCardStyle()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
