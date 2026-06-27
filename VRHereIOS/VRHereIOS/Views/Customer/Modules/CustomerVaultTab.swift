import SwiftUI

struct CustomerVaultTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Environment(\.openURL) private var openURL
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Document Vault")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                let documents = viewModel.orders.flatMap { $0.clientDocuments + $0.adminDocuments }
                
                if documents.isEmpty {
                    Text("Your uploaded certificates will display here once verified.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(documents) { doc in
                            HStack {
                                Image(systemName: "doc.fill")
                                    .foregroundColor(.primaryRed)
                                    .font(.title2)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(doc.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(doc.uploadedAt)
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Button(action: {
                                    if let url = getAbsoluteURL(path: doc.url) {
                                        openURL(url)
                                    }
                                }) {
                                    Image(systemName: "arrow.down.circle")
                                        .font(.title3)
                                        .foregroundColor(.blue)
                                }
                            }
                            .padding(12)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
