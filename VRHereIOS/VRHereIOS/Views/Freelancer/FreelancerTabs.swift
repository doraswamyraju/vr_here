import SwiftUI

// ==========================================
// 1. FREELANCER OVERVIEW TAB
// ==========================================
struct FreelancerOverviewTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    let userName: String
    let onSelectTab: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Welcome
                VStack(alignment: .leading, spacing: 4) {
                    Text("Welcome, \(userName)")
                        .font(.system(size: 22, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Track your assigned contract assignments and claim broadcasts.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Payout Quick Analytics
                let totalPaid = viewModel.ledger.filter { $0.status == "Paid" }.reduce(0.0) { $0 + $1.amount }
                let totalPending = viewModel.ledger.filter { $0.status != "Paid" }.reduce(0.0) { $0 + $1.amount }
                
                VStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("TOTAL PAID EARNINGS")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(.white.opacity(0.8))
                        Text("₹\(Int(totalPaid))")
                            .font(.system(size: 28, weight: .black))
                            .foregroundColor(.white)
                        
                        Text("Pending Approvals: ₹\(Int(totalPending))")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(.white.opacity(0.7))
                            .padding(.top, 4)
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        LinearGradient(colors: [Color.green, Color(red: 40/255, green: 140/255, blue: 90/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .cornerRadius(20)
                    .shadow(color: Color.green.opacity(0.15), radius: 8, x: 0, y: 4)
                    
                    HStack(spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Active Jobs")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.orders.count)")
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Open Pools")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.broadcasts.count)")
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                    }
                }
                .padding(.horizontal, 20)
                
                // Quick actions
                VStack(alignment: .leading, spacing: 12) {
                    Text("QUICK NAVIGATION")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 12) {
                        QuickActionRow(title: "View Broadcast Pool", subtitle: "Accept freelance jobs matching your skills", icon: "bell", color: .purple) {
                            onSelectTab("Broadcasts")
                        }
                        
                        QuickActionRow(title: "Active Processing Queue", subtitle: "Clock hours and complete checklist tasks", icon: "briefcase", color: .blue) {
                            onSelectTab("Queue")
                        }
                        
                        QuickActionRow(title: "Earning Ledger & Settlements", subtitle: "Track NEFT/IMPS payout statuses", icon: "indianrupeesign", color: .green) {
                            onSelectTab("Ledger")
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

struct QuickActionRow: View {
    let title: String
    let subtitle: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.system(size: 16, weight: .bold))
                    .frame(width: 36, height: 36)
                    .background(color.opacity(0.1))
                    .cornerRadius(8)
                
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textDark)
                    Text(subtitle)
                        .font(.system(size: 10))
                        .foregroundColor(.textMuted)
                }
                Spacer()
                Image(systemName: "chevron.forward")
                    .foregroundColor(.textMuted)
                    .font(.system(size: 11))
            }
            .padding(14)
            .background(Color.white)
            .cornerRadius(14)
            .shadow(color: Color.black.opacity(0.01), radius: 5, x: 0, y: 2)
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(Color.borderLight, lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
}

// ==========================================
// 2. FREELANCER BROADCASTS TAB
// ==========================================
struct FreelancerBroadcastsTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Open Broadcast Pools")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Accept pool job requests to start completing orders.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                if viewModel.broadcasts.isEmpty {
                    VStack(spacing: 16) {
                        Image(systemName: "bell.slash")
                            .font(.system(size: 32))
                            .foregroundColor(.textMuted)
                        Text("No active job broadcasts")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                        Text("New requests matching your specializations will appear here in real-time.")
                            .font(.system(size: 11))
                            .foregroundColor(.textMuted)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 40)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 80)
                } else {
                    VStack(spacing: 14) {
                        ForEach(viewModel.broadcasts) { job in
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Text(job.serviceName.uppercased())
                                        .font(.system(size: 8, weight: .black))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(.purple)
                                        .background(Color.purple.opacity(0.12))
                                        .cornerRadius(6)
                                    Spacer()
                                    let payout = Int(job.freelancerPayout ?? 0)
                                    Text("₹\(payout)")
                                        .font(.system(size: 16, weight: .black))
                                        .foregroundColor(.textDark)
                                }
                                
                                Text(job.packageName)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.textDark)
                                
                                Button(action: {
                                    viewModel.claimJob(orderId: job.id)
                                }) {
                                    Text("Accept Job Request")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.white)
                                        .frame(maxWidth: .infinity)
                                        .frame(height: 38)
                                        .background(Color.textDark)
                                        .cornerRadius(8)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(16)
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

// ==========================================
// 3. FREELANCER WORK QUEUE TAB
// ==========================================
struct FreelancerQueueTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    @Binding var selectedOrder: OrderResponse?
    
    @State private var clockOutNotes = ""
    @State private var isClockingOut = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let order = selectedOrder {
                    // Detailed Processing screen
                    Button(action: { selectedOrder = nil }) {
                        HStack(spacing: 6) {
                            Image(systemName: "chevron.backward")
                            Text("Back to Work Queue")
                        }
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.blue)
                    }
                    .padding(.top, 16)
                    .padding(.horizontal, 20)
                    
                    VStack(alignment: .leading, spacing: 10) {
                        Text(order.serviceName)
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(.textDark)
                        Text("Client: \(order.clientName)")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        
                        Divider().background(Color.borderLight)
                        
                        // Clocking status controls
                        VStack(alignment: .leading, spacing: 10) {
                            Text("TIME TRACKING CONTROLS")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.textMuted)
                            
                            HStack {
                                Spacer()
                                Button(action: {
                                    viewModel.clockIn(orderId: order.id)
                                }) {
                                    HStack {
                                        Image(systemName: "play.fill")
                                        Text("Clock In")
                                    }
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(width: 120, height: 38)
                                    .background(Color.green)
                                    .cornerRadius(8)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                                
                                Spacer()
                                
                                Button(action: {
                                    isClockingOut = true
                                }) {
                                    HStack {
                                        Image(systemName: "stop.fill")
                                        Text("Clock Out")
                                    }
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(width: 120, height: 38)
                                    .background(Color.red)
                                    .cornerRadius(8)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                                Spacer()
                            }
                        }
                        .padding(14)
                        .glassCard()
                        
                        // Subtasks progress checklist
                        VStack(alignment: .leading, spacing: 10) {
                            Text("ORDER PROGRESS & SUBTASKS")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.textMuted)
                            
                            if order.tasks.isEmpty {
                                Text("No subtasks specified for this service package.")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            } else {
                                ForEach(order.tasks) { t in
                                    HStack {
                                        Image(systemName: t.status.lowercased() == "completed" ? "checkmark.circle.fill" : "circle")
                                            .foregroundColor(t.status.lowercased() == "completed" ? .green : .textMuted)
                                        Text(t.title)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Spacer()
                                    }
                                    .padding(.vertical, 4)
                                }
                            }
                        }
                        .padding(14)
                        .glassCard()
                    }
                    .padding(.horizontal, 20)
                    .sheet(isPresented: $isClockingOut) {
                        VStack(spacing: 16) {
                            Text("Clock Out - Summary")
                                .font(.headline)
                            
                            CustomInputField(label: "Logs notes", placeholder: "Explain work accomplished", iconName: "pencil", text: $clockOutNotes)
                            
                            Button("Stop Shift Tracking") {
                                isClockingOut = false
                                viewModel.clockOut(orderId: order.id, notes: clockOutNotes)
                                clockOutNotes = ""
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        .padding(24)
                    }
                } else {
                    // Assigned Orders list
                    Text("Your Active Assignments")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    if viewModel.orders.isEmpty {
                        Text("No active contract orders assigned.")
                            .font(.system(size: 13))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        VStack(spacing: 12) {
                            ForEach(viewModel.orders) { order in
                                Button(action: { selectedOrder = order }) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(order.serviceName)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                                .multilineTextAlignment(.leading)
                                            let payout = Int(order.freelancerPayout ?? 0)
                                            Text("Client: \(order.clientName) • Payout: ₹\(payout)")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        Image(systemName: "chevron.forward")
                                            .foregroundColor(.textMuted)
                                    }
                                    .padding(16)
                                    .background(Color.white)
                                    .cornerRadius(16)
                                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(Color.borderLight, lineWidth: 1)
                                    )
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 4. FREELANCER LEDGER TAB
// ==========================================
struct FreelancerLedgerTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Settlements & Payout History")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.ledger.isEmpty {
                    Text("No payout receipts settlements calculated.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.ledger) { p in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(p.order?.packageName ?? "Referred Order")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text("Ref: \(p.transactionRef ?? "Processing") • Method: \(p.method)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                VStack(alignment: .trailing, spacing: 4) {
                                    Text("₹\(Int(p.amount))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(.green)
                                    Text(p.status)
                                        .font(.system(size: 8, weight: .bold))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .foregroundColor(p.status == "Paid" ? .green : .orange)
                                        .background((p.status == "Paid" ? Color.green : Color.orange).opacity(0.12))
                                        .cornerRadius(4)
                                }
                            }
                            .padding(14)
                            .glassCard()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 5. FREELANCER SUPPORT TAB
// ==========================================
struct FreelancerSupportTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    @State private var replyingTicketId = ""
    @State private var replyMessage = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if !replyingTicketId.isEmpty, let ticket = viewModel.supportTickets.first(where: { $0.id == replyingTicketId }) {
                    Button(action: { replyingTicketId = "" }) {
                        HStack(spacing: 6) {
                            Image(systemName: "chevron.backward")
                            Text("Back to Tickets")
                        }
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.blue)
                    }
                    .padding(.top, 16)
                    .padding(.horizontal, 20)
                    
                    VStack(alignment: .leading, spacing: 14) {
                        Text(ticket.subject)
                            .font(.system(size: 18, weight: .black))
                            .foregroundColor(.textDark)
                        Text(ticket.description)
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                        
                        Divider().background(Color.borderLight)
                        
                        // Messages threads
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(ticket.messages) { msg in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(msg.sender?.name ?? "Support Agent")
                                        .font(.system(size: 10, weight: .black))
                                        .foregroundColor(.textDark)
                                    Text(msg.message)
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                .padding(10)
                                .background(Color.bgLight)
                                .cornerRadius(10)
                            }
                        }
                        
                        // Reply box
                        HStack {
                            TextField("Enter message...", text: $replyMessage)
                                .font(.system(size: 12))
                            Button(action: {
                                viewModel.replyToTicket(ticketId: ticket.id, message: replyMessage)
                                replyMessage = ""
                            }) {
                                Image(systemName: "paperplane.fill")
                                    .foregroundColor(.white)
                                    .padding(8)
                                    .background(Color.blue)
                                    .cornerRadius(6)
                            }
                        }
                        .padding(8)
                        .background(Color.white)
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                    .padding(.horizontal, 20)
                } else {
                    Text("Support Desks")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    if viewModel.supportTickets.isEmpty {
                        Text("No tickets log found.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        VStack(spacing: 12) {
                            ForEach(viewModel.supportTickets) { ticket in
                                Button(action: { replyingTicketId = ticket.id }) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(ticket.subject)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text(ticket.status)
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        Image(systemName: "chevron.forward")
                                            .foregroundColor(.textMuted)
                                    }
                                    .padding(14)
                                    .glassCard()
                                    .padding(.horizontal, 20)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 6. FREELANCER NOTIFICATIONS TAB
// ==========================================
struct FreelancerNotificationsTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Notifications Center")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.notifications.isEmpty {
                    Text("No announcements feeds.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.notifications) { n in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(n.title)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(n.isRead ? .textMuted : .textDark)
                                    Text(n.message)
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                if !n.isRead {
                                    Button("Mark read") {
                                        viewModel.markNotificationAsRead(id: n.id)
                                    }
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.blue)
                                }
                            }
                            .padding(12)
                            .glassCard()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 7. FREELANCER SETTINGS TAB
// ==========================================
struct FreelancerSettingsTab: View {
    @ObservedObject var viewModel: FreelancerDashboardViewModel
    let onDeleteAccount: () -> Void
    
    @State private var showingDeleteAlert = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Freelancer Configuration Profile")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 16) {
                    CustomInputField(label: "Registered Full Name", placeholder: "Name", iconName: "person", text: $viewModel.nameInput)
                    CustomInputField(label: "Contact Phone", placeholder: "Phone", iconName: "phone", text: $viewModel.phoneInput)
                    CustomInputField(label: "Specializations / Skills", placeholder: "Skills e.g. Tally, GST", iconName: "wrench", text: $viewModel.skillsInput)
                    CustomInputField(label: "Experience Years", placeholder: "Experience years", iconName: "number", text: $viewModel.experienceInput)
                    CustomInputField(label: "Resume URL Link", placeholder: "Google drive links", iconName: "link", text: $viewModel.resumeUrlInput)
                    CustomInputField(label: "PAN ID verification", placeholder: "PAN Card", iconName: "creditcard", text: $viewModel.panCardInput)
                    
                    Divider().background(Color.borderLight)
                    
                    Text("Bank Payout Settlement Settings")
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.textDark)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    CustomInputField(label: "Account Holder Name", placeholder: "Holder name", iconName: "person.text.rectangle", text: $viewModel.bankAccountNameInput)
                    CustomInputField(label: "Bank Account Number", placeholder: "Account number", iconName: "number", text: $viewModel.bankAccountNumberInput)
                    CustomInputField(label: "IFSC Code", placeholder: "IFSC Code", iconName: "building.columns", text: $viewModel.bankIfscCodeInput)
                    CustomInputField(label: "Bank Name", placeholder: "E.g. HDFC Bank", iconName: "building", text: $viewModel.bankNameInput)
                    
                    Button(action: {
                        viewModel.updateProfile()
                    }) {
                        HStack {
                            if viewModel.isSavingProfile {
                                ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Image(systemName: "checkmark")
                                Text("SUBMIT PROFILE FOR APPROVAL")
                            }
                        }
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 44)
                        .background(Color.textDark)
                        .cornerRadius(10)
                    }
                    .disabled(viewModel.isSavingProfile)
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                // Danger Zone
                VStack(alignment: .leading, spacing: 12) {
                    Text("Danger Zone")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.primaryRed)
                    
                    Text("Permanently delete your freelancer account and all associated payout ledger history. This action is irreversible.")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                        .lineLimit(nil)
                    
                    Button(action: {
                        showingDeleteAlert = true
                    }) {
                        Text("Delete Account")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .alert(isPresented: $showingDeleteAlert) {
            Alert(
                title: Text("Delete Account?"),
                message: Text("Are you sure you want to permanently delete your freelancer account? All your ledger and payout history will be destroyed immediately. This cannot be undone."),
                primaryButton: .destructive(Text("Delete Permanently")) {
                    onDeleteAccount()
                },
                secondaryButton: .cancel()
            )
        }
    }
}
