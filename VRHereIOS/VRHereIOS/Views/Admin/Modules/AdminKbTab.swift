import SwiftUI

struct AdminKbTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("KB Hub & Documents")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let articles = [
                        ("Private Ltd Incorporation Checklist", "Step-by-step company registration verification"),
                        ("GST Registration Mandatory Docs", "State-wise document proof requirements"),
                        ("Trademark Class Finder Guideline", "Classes lookup and search tools description"),
                        ("ITR-3 Filing Instructions", "Income tax schedule for business partners")
                    ]
                    
                    ForEach(articles, id: \.0) { title, desc in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(title)
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(desc)
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
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
