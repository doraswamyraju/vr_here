import SwiftUI

struct AdminSupportTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Client Support Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let chats = [
                        ("Manojh K.", "Where is my DIN certificate copy?", "Active"),
                        ("Vinitha S.", "Can I change my registered email?", "Waiting"),
                        ("Dora Raju", "Payment failed for IEC filing", "Resolved")
                    ]
                    
                    ForEach(chats, id: \.0) { client, msg, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(client)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(msg)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Resolved" ? Color.green : Color.blue)
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
