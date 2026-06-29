import SwiftUI

struct AdminSupportTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("CLIENT TICKETS & TELEPHONY")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Client Support Desk")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Resolve billing issues, certificate queries, and direct client chats.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 25/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Chats listing
                VStack(alignment: .leading, spacing: 14) {
                    Text("ACTIVE SUPPORT CHATS")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    let chats = [
                        ("Manojh K.", "Where is my DIN certificate copy?", "Active", "09:42 AM"),
                        ("Vinitha S.", "Can I change my registered email?", "Waiting", "Yesterday"),
                        ("Dora Raju", "Payment failed for IEC filing", "Resolved", "2 days ago"),
                        ("Venkata R.", "LLP Agreement draft reviewed.", "Active", "3 days ago")
                    ]
                    
                    VStack(spacing: 12) {
                        ForEach(chats, id: \.0) { client, msg, status, time in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(client)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    
                                    // Status tag
                                    Text(status.uppercased())
                                        .font(.system(size: 8, weight: .bold))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(status == "Resolved" ? .green : (status == "Waiting" ? .orange : .blue))
                                        .background((status == "Resolved" ? Color.green : (status == "Waiting" ? Color.orange : Color.blue)).opacity(0.12))
                                        .cornerRadius(6)
                                }
                                
                                Text(msg)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    Text("Updated: \(time)")
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    
                                    Button(action: {
                                        viewModel.toastMessage = "Reply dialog opened for \(client)"
                                    }) {
                                        Text("REPLY")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.primaryRed)
                                    }
                                }
                            }
                            .padding(14)
                            .background(Color.white)
                            .cornerRadius(16)
                            .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
