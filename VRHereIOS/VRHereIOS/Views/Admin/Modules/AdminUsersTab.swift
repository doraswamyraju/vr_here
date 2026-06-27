import SwiftUI

struct AdminUsersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("User Matrix Control")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                ForEach(viewModel.employees) { emp in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(emp.name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(emp.email)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        Text(emp.role.capitalized)
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.blue)
                    }
                    .glassCardStyle()
                    .padding(.horizontal, 20)
                }
                Spacer().frame(height: 100)
            }
        }
    }
}
