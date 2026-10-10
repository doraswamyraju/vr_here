import SwiftUI

struct AdminSupportTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var searchQuery: String = ""
    @State private var statusFilter: String = "All"
    @State private var selectedTicket: TicketResponse? = nil
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("CLIENT TICKETS & TELEPHONY • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Client Support Desk")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        
                        Button(action: { viewModel.syncDashboardData() }) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .padding(10)
                                .background(Color.white.opacity(0.15))
                                .cornerRadius(10)
                        }
                    }
                    
                    Text("Resolve client compliance queries, certificate delivery issues, billing clarifications, and manage real-time communication threads.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 25/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Search & Filter Bar
                VStack(spacing: 10) {
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.textMuted)
                        TextField("Search tickets by subject, client...", text: $searchQuery)
                            .font(.system(size: 12))
                        if !searchQuery.isEmpty {
                            Button(action: { searchQuery = "" }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.textMuted)
                            }
                        }
                    }
                    .padding(10)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                    
                    HStack(spacing: 8) {
                        ForEach(["All", "Open", "In Progress", "Resolved", "Closed"], id: \.self) { filter in
                            let isSel = statusFilter == filter
                            Button(action: { statusFilter = filter }) {
                                Text(filter)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .foregroundColor(isSel ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSel ? Color.indigoCustom : Color.white)
                                    .cornerRadius(8)
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(isSel ? Color.indigoCustom : Color.borderLight, lineWidth: 1))
                            }
                        }
                        Spacer()
                    }
                }
                .padding(.horizontal, 20)
                
                // Tickets List
                VStack(alignment: .leading, spacing: 14) {
                    let filtered = viewModel.tickets.filter { t in
                        let matchesSearch = searchQuery.isEmpty ||
                            t.subject.localizedCaseInsensitiveContains(searchQuery) ||
                            t.description.localizedCaseInsensitiveContains(searchQuery) ||
                            (t.user?.name ?? "").localizedCaseInsensitiveContains(searchQuery)
                        let matchesStatus = statusFilter == "All" ||
                            (statusFilter == "Open" && (t.status.lowercased() == "open" || t.status.lowercased() == "pending")) ||
                            (statusFilter == "In Progress" && t.status.lowercased() == "in progress") ||
                            (statusFilter == "Resolved" && t.status.lowercased() == "resolved") ||
                            (statusFilter == "Closed" && t.status.lowercased() == "closed")
                        return matchesSearch && matchesStatus
                    }
                    
                    if filtered.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "envelope.badge")
                                .font(.system(size: 32))
                                .foregroundColor(.textMuted)
                            Text("No client support tickets found.")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(40)
                        .background(Color.white)
                        .cornerRadius(16)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                    } else {
                        ForEach(filtered) { ticket in
                            Button(action: { selectedTicket = ticket }) {
                                VStack(alignment: .leading, spacing: 10) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(ticket.subject)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text("Client: \(ticket.user?.name ?? "Client") • \(ticket.user?.email ?? "")")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        
                                        Text(ticket.status.uppercased())
                                            .font(.system(size: 8, weight: .black))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .foregroundColor(statusColor(ticket.status))
                                            .background(statusColor(ticket.status).opacity(0.12))
                                            .cornerRadius(6)
                                    }
                                    
                                    Text(ticket.description)
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                        .lineLimit(2)
                                    
                                    Divider().background(Color.borderLight)
                                    
                                    HStack {
                                        HStack(spacing: 4) {
                                            Image(systemName: "bubble.left.and.bubble.right.fill")
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                            Text("\(ticket.messages.count) messages")
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        Text("Open Thread →")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(.indigoCustom)
                                    }
                                }
                                .padding(14)
                                .background(Color.white)
                                .cornerRadius(16)
                                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(item: $selectedTicket) { ticket in
            AdminTicketChatSheet(ticket: ticket) {
                viewModel.syncDashboardData()
            }
        }
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "resolved": return .green
        case "closed": return .gray
        case "in progress": return .orange
        default: return .blue
        }
    }
}

// MARK: - Admin Ticket Chat Sheet Subview
struct AdminTicketChatSheet: View {
    let ticket: TicketResponse
    let onUpdated: () -> Void
    
    @Environment(\.presentationMode) var presentationMode
    @State private var replyText: String = ""
    @State private var isSending: Bool = false
    @State private var currentStatus: String = "Open"
    
    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Ticket Subject Bar
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(ticket.subject)
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.textDark)
                        Spacer()
                        Menu {
                            ForEach(["Open", "In Progress", "Resolved", "Closed"], id: \.self) { st in
                                Button(st) {
                                    updateStatus(st)
                                }
                            }
                        } label: {
                            Text(currentStatus.uppercased())
                                .font(.system(size: 9, weight: .black))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .foregroundColor(.white)
                                .background(Color.indigoCustom)
                                .cornerRadius(6)
                        }
                    }
                    Text("Client: \(ticket.user?.name ?? "Client") (\(ticket.user?.email ?? ""))")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                .padding(14)
                .background(Color.bgLight)
                .overlay(Rectangle().frame(height: 1).foregroundColor(Color.borderLight), alignment: .bottom)
                
                // Messages Scroll
                ScrollView {
                    VStack(spacing: 12) {
                        // Original Issue Bubble
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(ticket.user?.name ?? "Client")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Text(ticket.createdAt.prefix(10))
                                    .font(.system(size: 9))
                                    .foregroundColor(.textMuted)
                            }
                            Text(ticket.description)
                                .font(.system(size: 12))
                                .foregroundColor(.textDark)
                        }
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(12)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                        
                        ForEach(ticket.messages) { msg in
                            let isStaff = msg.sender?.role == "admin" || msg.sender?.role == "employee"
                            HStack {
                                if isStaff { Spacer() }
                                VStack(alignment: isStaff ? .trailing : .leading, spacing: 4) {
                                    Text(isStaff ? "VR Here Team" : (msg.sender?.name ?? "Client"))
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(isStaff ? .white.opacity(0.8) : .textMuted)
                                    Text(msg.message)
                                        .font(.system(size: 12))
                                        .foregroundColor(isStaff ? .white : .textDark)
                                }
                                .padding(12)
                                .background(isStaff ? Color.indigoCustom : Color.white)
                                .cornerRadius(12)
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(isStaff ? Color.clear : Color.borderLight, lineWidth: 1))
                                if !isStaff { Spacer() }
                            }
                        }
                    }
                    .padding(16)
                }
                
                // Reply Input Bar
                HStack(spacing: 8) {
                    TextField("Type reply to client...", text: $replyText)
                        .font(.system(size: 13))
                        .padding(10)
                        .background(Color.white)
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                    
                    Button(action: sendReply) {
                        if isSending {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Image(systemName: "paperplane.fill")
                                .font(.system(size: 14))
                                .foregroundColor(.white)
                                .padding(12)
                                .background(Color.indigoCustom)
                                .cornerRadius(10)
                        }
                    }
                    .disabled(replyText.trimmingCharacters(in: .whitespaces).isEmpty || isSending)
                }
                .padding(12)
                .background(Color.bgLight)
            }
            .navigationTitle("Support Thread")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Close") { presentationMode.wrappedValue.dismiss() }
                }
            }
            .onAppear {
                currentStatus = ticket.status
            }
        }
    }
    
    private func sendReply() {
        let msg = replyText.trimmingCharacters(in: .whitespaces)
        guard !msg.isEmpty else { return }
        isSending = true
        Task {
            do {
                _ = try await NetworkManager.shared.addTicketMessage(ticketId: ticket.idVal, message: msg)
                replyText = ""
                onUpdated()
            } catch {
                print("Failed to send message: \(error)")
            }
            isSending = false
        }
    }
    
    private func updateStatus(_ st: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.updateTicketStatus(id: ticket.idVal, status: st)
                currentStatus = st
                onUpdated()
            } catch {
                print("Failed to update status: \(error)")
            }
        }
    }
}
