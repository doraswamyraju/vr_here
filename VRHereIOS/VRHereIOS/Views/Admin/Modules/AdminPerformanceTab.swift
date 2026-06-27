import SwiftUI

struct AdminPerformanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Performance Metrics")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    ForEach(viewModel.employees) { emp in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(emp.name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Assigned Tasks: \(Int.random(in: 2...8))")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 4) {
                                Text("95% SLA")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.green)
                            }
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
