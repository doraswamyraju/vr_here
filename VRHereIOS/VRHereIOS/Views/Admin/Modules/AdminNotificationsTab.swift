import SwiftUI

struct AdminNotificationsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("SYSTEM ALERTS & SYSTEM STATUS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Admin Notifications")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Audit system logs, client registrations, and action requirements.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 45/255, green: 15/255, blue: 15/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Notifications list
                VStack(spacing: 12) {
                    if viewModel.notifications.isEmpty {
                        Text("No notifications received")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 30)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else {
                        ForEach(viewModel.notifications) { note in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(alignment: .top, spacing: 10) {
                                    // Status Dot indicator
                                    Circle()
                                        .fill(note.isRead ? Color.gray.opacity(0.4) : Color.primaryRed)
                                        .frame(width: 8, height: 8)
                                        .padding(.top, 4)
                                    
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(note.title)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(note.message)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    Text("Logged: \(note.createdAt.prefix(10))")
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    
                                    if !note.isRead {
                                        Button(action: {
                                            viewModel.markNotificationAsRead(id: note.id)
                                        }) {
                                            Text("MARK AS READ")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(.primaryRed)
                                        }
                                    } else {
                                        Text("READ")
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(.textMuted)
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
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
