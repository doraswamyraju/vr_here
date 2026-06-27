import SwiftUI

struct AdminNotificationsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("System Notifications")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    if viewModel.notifications.isEmpty {
                        Text("No notifications logged.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        ForEach(viewModel.notifications) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.title)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(item.isRead ? .textMuted : .textDark)
                                    Text(item.message)
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                if !item.isRead {
                                    Button("Mark Read") {
                                        viewModel.markNotificationAsRead(id: item.id)
                                    }
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.blue)
                                }
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
