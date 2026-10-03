import SwiftUI

struct CustomerSupportTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    @State private var selectedFilter = "all" // "all" | "open" | "progress" | "closed"
    @State private var selectedTicket: TicketResponse? = nil
    @State private var showRaiseTicketSheet = false
    
    // New Ticket Form State
    @State private var selectedCategory = "Service"
    @State private var subjectInput = ""
    @State private var descriptionInput = ""
    @State private var priorityInput = "Medium"
    @State private var isSubmitting = false
    
    // Conversation Reply State
    @State private var replyInput = ""
    @State private var isSendingReply = false
    
    @Environment(\.openURL) private var openURL
    
    var filteredTickets: [TicketResponse] {
        viewModel.tickets.filter { ticket in
            let st = ticket.status.lowercased()
            switch selectedFilter {
            case "open":
                return st == "open"
            case "progress":
                return st == "in progress" || st == "progress" || st == "resolved"
            case "closed":
                return st == "closed"
            default:
                return true
            }
        }
    }
    
    var body: some View {
        Group {
            if let ticket = selectedTicket {
                ticketConversationView(ticket: ticket)
            } else {
                mainTicketCenterView
            }
        }
        .sheet(isPresented: $showRaiseTicketSheet) {
            raiseTicketModalSheet
        }
    }
    
    // MARK: - Main Ticket Center
    private var mainTicketCenterView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // 1. Hero Advisory Banner
                heroBanner
                
                // 2. Direct Helpline Quick Action Cards
                helplineCardsRow
                
                // 3. Status Filter Chips
                filterChipsRow
                
                // 4. Ticket Cards List
                if filteredTickets.isEmpty {
                    emptyTicketsCard
                } else {
                    LazyVStack(spacing: 12) {
                        ForEach(filteredTickets) { ticket in
                            ticketCard(ticket: ticket)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
            .padding(.horizontal, 16)
            .padding(.top, 16)
        }
    }
    
    // MARK: - Hero Banner
    private var heroBanner: some View {
        ZStack(alignment: .leading) {
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [Color(red: 136/255, green: 19/255, blue: 55/255), Color(red: 190/255, green: 18/255, blue: 60/255), Color(red: 225/255, green: 29/255, blue: 72/255)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Text("CA & LEGAL ADVISORY DESK")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.white.opacity(0.2))
                        .clipShape(Capsule())
                }
                
                Text("Help & Support Tickets")
                    .font(.system(size: 20, weight: .black))
                    .foregroundColor(.white)
                
                Text("Raise tickets directly with CA/CS experts and compliance leads for priority assistance.")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(Color(red: 255/255, green: 228/255, blue: 230/255))
                    .fixedSize(horizontal: false, vertical: true)
                
                Button(action: {
                    showRaiseTicketSheet = true
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("Raise New Support Ticket")
                            .font(.system(size: 11, weight: .black))
                    }
                    .foregroundColor(Color(red: 190/255, green: 18/255, blue: 60/255))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .background(Color.white)
                    .cornerRadius(10)
                    .shadow(color: Color.black.opacity(0.1), radius: 3, x: 0, y: 2)
                }
                .padding(.top, 4)
            }
            .padding(18)
        }
    }
    
    // MARK: - Direct Helpline Cards Row
    private var helplineCardsRow: some View {
        HStack(spacing: 12) {
            // WhatsApp
            Button(action: {
                if let url = URL(string: "https://wa.me/918008530606") {
                    openURL(url)
                }
            }) {
                HStack(spacing: 10) {
                    Image(systemName: "message.fill")
                        .font(.system(size: 16))
                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("WhatsApp Desk")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                        Text("Instant CA Support")
                            .font(.system(size: 10))
                            .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                    }
                    Spacer()
                }
                .padding(12)
                .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                .cornerRadius(14)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                )
            }
            
            // Phone Helpline
            Button(action: {
                if let url = URL(string: "tel:918008530606") {
                    openURL(url)
                }
            }) {
                HStack(spacing: 10) {
                    Image(systemName: "phone.fill")
                        .font(.system(size: 16))
                        .foregroundColor(Color(red: 29/255, green: 78/255, blue: 216/255))
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Call Helpline")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(Color(red: 30/255, green: 64/255, blue: 175/255))
                        Text("+91 80085 30606")
                            .font(.system(size: 10))
                            .foregroundColor(Color(red: 37/255, green: 99/255, blue: 235/255))
                    }
                    Spacer()
                }
                .padding(12)
                .background(Color(red: 239/255, green: 246/255, blue: 255/255))
                .cornerRadius(14)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(red: 191/255, green: 219/255, blue: 254/255), lineWidth: 1)
                )
            }
        }
    }
    
    // MARK: - Filter Chips Row
    private var filterChipsRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                filterChip(id: "all", label: "All (\(viewModel.tickets.count))")
                filterChip(id: "open", label: "Open (\(viewModel.tickets.count { $0.status == "Open" }))")
                filterChip(id: "progress", label: "In Progress (\(viewModel.tickets.count { $0.status == "In Progress" || $0.status == "Resolved" }))")
                filterChip(id: "closed", label: "Closed (\(viewModel.tickets.count { $0.status == "Closed" }))")
            }
        }
    }
    
    private func filterChip(id: String, label: String) -> some View {
        let isSelected = selectedFilter == id
        return Button(action: {
            selectedFilter = id
        }) {
            Text(label)
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(isSelected ? Color.primaryRed : Color.white)
                .cornerRadius(10)
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(isSelected ? Color.primaryRed : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
        }
    }
    
    // MARK: - Ticket Card
    private func ticketCard(ticket: TicketResponse) -> some View {
        Button(action: {
            selectedTicket = ticket
        }) {
            VStack(alignment: .leading, spacing: 10) {
                // Header tags
                HStack {
                    HStack(spacing: 6) {
                        Text("#TCK-\(String(ticket.id.suffix(6)).uppercased())")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(5)
                        
                        Text(ticket.priority.uppercased())
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(Color(red: 190/255, green: 18/255, blue: 60/255))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                            .cornerRadius(5)
                    }
                    
                    Spacer()
                    
                    statusPill(status: ticket.status)
                }
                
                Text(ticket.subject)
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .lineLimit(1)
                
                Text(ticket.description)
                    .font(.system(size: 11))
                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    .lineLimit(2)
                
                Divider()
                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                
                HStack {
                    Text("\(ticket.messages.count) Messages • Tapped to Open Discussion")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    
                    Spacer()
                    
                    HStack(spacing: 2) {
                        Text("View Chat")
                            .font(.system(size: 11, weight: .black))
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .bold))
                    }
                    .foregroundColor(Color.primaryRed)
                }
            }
            .padding(14)
            .background(Color.white)
            .cornerRadius(16)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.02), radius: 4, x: 0, y: 2)
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    private func statusPill(status: String) -> some View {
        let isClosed = status == "Closed"
        let isProgress = status == "In Progress" || status == "Resolved"
        
        return Text(status.uppercased())
            .font(.system(size: 9, weight: .black))
            .foregroundColor(isClosed ? Color(red: 100/255, green: 116/255, blue: 139/255) : (isProgress ? Color(red: 29/255, green: 78/255, blue: 216/255) : Color(red: 180/255, green: 83/255, blue: 9/255)))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(isClosed ? Color(red: 241/255, green: 245/255, blue: 249/255) : (isProgress ? Color(red: 219/255, green: 234/255, blue: 254/255) : Color(red: 254/255, green: 243/255, blue: 199/255)))
            .cornerRadius(6)
    }
    
    // MARK: - Empty State
    private var emptyTicketsCard: some View {
        VStack(spacing: 12) {
            Image(systemName: "headphones.circle.fill")
                .font(.system(size: 40))
                .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
            
            Text("No support tickets in this view")
                .font(.system(size: 13, weight: .bold))
                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
            
            Button(action: {
                showRaiseTicketSheet = true
            }) {
                Text("Raise New Support Ticket")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 9)
                    .background(Color.primaryRed)
                    .cornerRadius(10)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(32)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
    }
    
    // MARK: - Conversation Detail View
    private func ticketConversationView(ticket: TicketResponse) -> some View {
        let isClosed = ticket.status == "Closed"
        
        return VStack(spacing: 0) {
            // Header Bar
            HStack(spacing: 12) {
                Button(action: {
                    selectedTicket = nil
                }) {
                    Image(systemName: "arrow.left")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .frame(width: 36, height: 36)
                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        .clipShape(Circle())
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(ticket.subject)
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .lineLimit(1)
                    
                    Text("Ticket #\(String(ticket.id.suffix(6)).uppercased()) • Priority: \(ticket.priority)")
                        .font(.system(size: 10))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                
                Spacer()
                
                statusPill(status: ticket.status)
            }
            .padding(14)
            .background(Color.white)
            .overlay(
                Rectangle()
                    .frame(height: 1)
                    .foregroundColor(Color(red: 226/255, green: 232/255, blue: 240/255)),
                alignment: .bottom
            )
            
            // Conversation Scroll
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Initial Query Card
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            HStack(spacing: 6) {
                                Image(systemName: "person.fill")
                                    .font(.system(size: 10))
                                    .foregroundColor(Color.primaryRed)
                                    .frame(width: 22, height: 22)
                                    .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                    .clipShape(Circle())
                                
                                Text("You (Client)")
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            }
                            
                            Spacer()
                            
                            Text(ticket.createdAt.prefix(10))
                                .font(.system(size: 9))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        
                        Text(ticket.description)
                            .font(.system(size: 12))
                            .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                            .lineSpacing(3)
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                    
                    // Replies
                    ForEach(ticket.messages) { msg in
                        let isClientMessage = msg.sender?.role == "client" || msg.sender == nil
                        
                        HStack {
                            if isClientMessage { Spacer(minLength: 40) }
                            
                            VStack(alignment: isClientMessage ? .trailing : .leading, spacing: 4) {
                                Text(isClientMessage ? "You" : (msg.sender?.name ?? "Compliance Lead / CA"))
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(isClientMessage ? Color(red: 254/255, green: 205/255, blue: 211/255) : Color(red: 37/255, green: 99/255, blue: 235/255))
                                
                                Text(msg.message)
                                    .font(.system(size: 12))
                                    .foregroundColor(isClientMessage ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                    .lineSpacing(2)
                            }
                            .padding(12)
                            .background(isClientMessage ? Color.primaryRed : Color.white)
                            .cornerRadius(14)
                            .overlay(
                                RoundedRectangle(cornerRadius: 14)
                                    .stroke(isClientMessage ? Color.primaryRed : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                            
                            if !isClientMessage { Spacer(minLength: 40) }
                        }
                    }
                }
                .padding(16)
            }
            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
            
            // Bottom Reply Bar (if active)
            if !isClosed {
                HStack(spacing: 8) {
                    TextField("Type reply for CA advisor...", text: $replyInput)
                        .font(.system(size: 12))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        .cornerRadius(20)
                    
                    Button(action: {
                        guard !replyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
                        let text = replyInput
                        isSendingReply = true
                        Task {
                            let updated = await viewModel.replyToTicket(ticketId: ticket.id, message: text)
                            if let updated = updated {
                                selectedTicket = updated
                                replyInput = ""
                            }
                            isSendingReply = false
                        }
                    }) {
                        if isSendingReply {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .frame(width: 40, height: 40)
                                .background(Color.primaryRed)
                                .clipShape(Circle())
                        } else {
                            Image(systemName: "paperplane.fill")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .frame(width: 40, height: 40)
                                .background(Color.primaryRed)
                                .clipShape(Circle())
                        }
                    }
                    .disabled(isSendingReply || replyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(12)
                .background(Color.white)
                .overlay(
                    Rectangle()
                        .frame(height: 1)
                        .foregroundColor(Color(red: 226/255, green: 232/255, blue: 240/255)),
                    alignment: .top
                )
            }
        }
    }
    
    // MARK: - Raise Ticket Modal Sheet
    private var raiseTicketModalSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    // Header Subtitle
                    HStack {
                        Text("NEW SUPPORT REQUEST")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(Color.primaryRed)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                            .clipShape(Capsule())
                    }
                    
                    // 1. Department / Category Grid
                    VStack(alignment: .leading, spacing: 8) {
                        Text("SELECT DEPARTMENT / CATEGORY")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                            categoryCard(key: "Workflow", title: "Workflow Issue", desc: "Internal blocker, audit flag, or document gap", icon: "shield.lefthalf.filled")
                            categoryCard(key: "Technical", title: "Technical", desc: "Website issues, login, file uploads, errors", icon: "wrench.and.screwdriver")
                            categoryCard(key: "Service", title: "Service", desc: "Filing status, MCA queries, CA review", icon: "briefcase.fill")
                            categoryCard(key: "Support", title: "Support", desc: "Billing, tax invoices, receipts, inquiries", icon: "headphones")
                        }
                    }
                    
                    // 2. Urgency Level
                    VStack(alignment: .leading, spacing: 8) {
                        Text("URGENCY LEVEL")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        
                        HStack(spacing: 8) {
                            ForEach(["Low", "Medium", "High", "Urgent"], id: \.self) { p in
                                let isSel = priorityInput == p
                                Button(action: {
                                    priorityInput = p
                                }) {
                                    Text(p)
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(isSel ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 9)
                                        .background(isSel ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 248/255, green: 250/255, blue: 252/255))
                                        .cornerRadius(10)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 10)
                                                .stroke(isSel ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                        )
                                }
                            }
                        }
                    }
                    
                    // 3. Subject / Topic
                    VStack(alignment: .leading, spacing: 6) {
                        Text("SUBJECT / TOPIC")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        
                        TextField("e.g. Query regarding DSC signature in MCA filing", text: $subjectInput)
                            .font(.system(size: 12))
                            .padding(12)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                    }
                    
                    // 4. Detailed Explanation
                    VStack(alignment: .leading, spacing: 6) {
                        Text("DETAILED EXPLANATION")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        
                        TextEditor(text: $descriptionInput)
                            .font(.system(size: 12))
                            .frame(height: 100)
                            .padding(8)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                    }
                    
                    // Submit & Cancel Buttons
                    HStack(spacing: 12) {
                        Button(action: {
                            showRaiseTicketSheet = false
                        }) {
                            Text("Cancel")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                .frame(maxWidth: .infinity)
                                .frame(height: 44)
                        }
                        
                        Button(action: {
                            guard !subjectInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                                  !descriptionInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
                            
                            isSubmitting = true
                            Task {
                                let success = await viewModel.createSupportTicket(
                                    category: selectedCategory,
                                    subject: subjectInput,
                                    description: descriptionInput,
                                    priority: priorityInput
                                )
                                if success {
                                    subjectInput = ""
                                    descriptionInput = ""
                                    showRaiseTicketSheet = false
                                }
                                isSubmitting = false
                            }
                        }) {
                            HStack(spacing: 6) {
                                if isSubmitting {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                } else {
                                    Image(systemName: "paperplane.fill")
                                        .font(.system(size: 11, weight: .bold))
                                    Text("SUBMIT TICKET")
                                        .font(.system(size: 11, weight: .black))
                                }
                            }
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.primaryRed)
                            .cornerRadius(12)
                        }
                        .disabled(isSubmitting || subjectInput.isEmpty || descriptionInput.isEmpty)
                    }
                    .padding(.top, 8)
                }
                .padding(20)
            }
            .navigationTitle("Raise Support Ticket")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        showRaiseTicketSheet = false
                    }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    }
                }
            }
        }
    }
    
    private func categoryCard(key: String, title: String, desc: String, icon: String) -> some View {
        let isSelected = selectedCategory == key
        return Button(action: {
            selectedCategory = key
        }) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Image(systemName: icon)
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(isSelected ? Color(red: 244/255, green: 63/255, blue: 94/255) : Color(red: 15/255, green: 23/255, blue: 42/255))
                    
                    Text(title)
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(isSelected ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                }
                
                Text(desc)
                    .font(.system(size: 9))
                    .foregroundColor(isSelected ? Color(red: 148/255, green: 163/255, blue: 184/255) : Color(red: 100/255, green: 116/255, blue: 139/255))
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(isSelected ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 248/255, green: 250/255, blue: 252/255))
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(isSelected ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
}
