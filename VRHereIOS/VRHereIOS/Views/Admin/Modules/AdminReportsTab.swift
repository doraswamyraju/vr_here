import SwiftUI

struct AdminReportsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Business Reports")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("Conversion Rate")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    Text("68.4%")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.blue)
                    
                    ProgressView(value: 0.68)
                        .tint(.blue)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("Monthly Goal Growth")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    Text("₹1,25,000 / ₹2,00,000")
                        .font(.system(size: 16, weight: .black))
                        .foregroundColor(.green)
                    
                    ProgressView(value: 0.62)
                        .tint(.green)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
