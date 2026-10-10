import SwiftUI

struct AdminFreelancersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var activeSubTab: FreelancerSubTab = .broadcast
    @State private var searchQuery = ""
    @State private var statusFilter = "All"
    
    // Broadcast state
    @State private var broadcastPayoutAmounts: [String: String] = [:]
    @State private var isBroadcastingId: String? = nil
    
    // Direct Assign state
    @State private var selectedFreelancerForOrder: [String: String] = [:]
    
    // Freelancer Applicants state
    @State private var applicants: [FreelancerApplicant] = []
    @State private var isLoadingApplicants = false
    @State private var selectedApplicantForView: FreelancerApplicant? = nil
    @State private var applicantToEdit: FreelancerApplicant? = nil
    @State private var editName = ""
    @State private var editEmail = ""
    @State private var editPhone = ""
    @State private var editSkills = ""
    @State private var editExp = ""
    @State private var editPan = ""
    @State private var editBankName = ""
    @State private var editAccountNo = ""
    @State private var editIfsc = ""
    @State private var isSavingEdit = false
    
    // Payouts Ledger state
    @State private var payoutRequests: [FreelancerPayoutItem] = []
    @State private var isLoadingPayouts = false
    @State private var payoutToSettle: FreelancerPayoutItem? = nil
    @State private var settleMethod = "NEFT"
    @State private var settleTxnRef = ""
    @State private var settleNotes = ""
    @State private var isSettling = false
    
    // Live Attendance state
    @State private var liveSessions: [AttendanceSummaryItem] = []
    @State private var isLoadingLive = false
    
    enum FreelancerSubTab: String, CaseIterable {
        case broadcast = "Work Broadcast"
        case registrations = "Registrations"
        case payouts = "Payouts Ledger"
        case liveAttendance = "Live Attendance"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Top Header Console Banner
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("GIG ECONOMY & CONTRACTORS HUB")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Freelancer Hub")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Outsource client orders, broadcast tasks with dedicated budgets, verify contractor credentials, and settle bank payouts.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.8))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 20/255, blue: 10/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // 4 Sub-Tabs Switcher Bar
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(FreelancerSubTab.allCases, id: \.self) { tab in
                            let isSelected = activeSubTab == tab
                            Button(action: {
                                activeSubTab = tab
                                loadSubTabData(tab: tab)
                            }) {
                                HStack(spacing: 6) {
                                    switch tab {
                                    case .broadcast: Image(systemName: "bolt.fill")
                                    case .registrations: Image(systemName: "person.text.rectangle")
                                    case .payouts: Image(systemName: "indianrupeesign.circle.fill")
                                    case .liveAttendance: Image(systemName: "clock.badge.checkmark.fill")
                                    }
                                    Text(tab.rawValue)
                                }
                                .font(.system(size: 12, weight: .bold))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 8)
                                .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                .background(isSelected ? Color.orange : Color.white)
                                .cornerRadius(12)
                                .shadow(color: isSelected ? Color.orange.opacity(0.3) : Color.clear, radius: 4, y: 2)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(isSelected ? Color.orange : Color.borderLight, lineWidth: 1)
                                )
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Sub-Tab Content
                VStack(spacing: 16) {
                    switch activeSubTab {
                    case .broadcast:
                        workBroadcastSection
                    case .registrations:
                        registrationsSection
                    case .payouts:
                        payoutsSection
                    case .liveAttendance:
                        liveAttendanceSection
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            loadSubTabData(tab: activeSubTab)
        }
        .sheet(item: $selectedApplicantForView) { app in
            applicantDetailSheet(app: app)
        }
        .sheet(item: $applicantToEdit) { app in
            applicantEditSheet(app: app)
        }
        .sheet(item: $payoutToSettle) { pay in
            settlePayoutSheet(pay: pay)
        }
    }
    
    // MARK: - SubTab 1: Work Broadcast
    private var workBroadcastSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "bolt.badge.clock.fill")
                    .foregroundColor(.orange)
                Text("ORDERS AVAILABLE FOR FREELANCE BROADCAST")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
                Text("\(viewModel.orders.filter { $0.status.lowercased() != "completed" }.count) Active")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textMuted)
            }
            
            let pendingOrders = viewModel.orders.filter { $0.status.lowercased() != "completed" }
            
            if pendingOrders.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray.fill")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No active orders available for freelance broadcast.")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
                .background(Color.white)
                .cornerRadius(16)
            } else {
                ForEach(pendingOrders) { ord in
                    freelanceOrderBroadcastCard(order: ord)
                }
            }
        }
    }
    
    private func freelanceOrderBroadcastCard(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header Info
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(order.serviceName)
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.textDark)
                    Text("Client: \(order.clientName) • Package: \(order.packageName)")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                Spacer()
                
                VStack(alignment: .trailing, spacing: 3) {
                    Text("₹\(Int(order.price))")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                    
                    if order.broadcastStatus == "Broadcasted" {
                        Text("BROADCASTED")
                            .font(.system(size: 8, weight: .black))
                            .foregroundColor(.purple)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.purple.opacity(0.12))
                            .cornerRadius(6)
                    } else if order.broadcastStatus == "Claimed" {
                        Text("CLAIMED")
                            .font(.system(size: 8, weight: .black))
                            .foregroundColor(.green)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.green.opacity(0.12))
                            .cornerRadius(6)
                    } else {
                        Text("INTERNAL ONLY")
                            .font(.system(size: 8, weight: .black))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.gray.opacity(0.12))
                            .cornerRadius(6)
                    }
                }
            }
            
            Divider().background(Color.borderLight)
            
            // Broadcast Control
            VStack(alignment: .leading, spacing: 8) {
                Text("OPTION A: BROADCAST TO FREELANCE POOL")
                    .font(.system(size: 9, weight: .black))
                    .foregroundColor(.textMuted)
                
                HStack(spacing: 8) {
                    HStack {
                        Text("₹")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        TextField("Payout INR", text: Binding(
                            get: { broadcastPayoutAmounts[order.id] ?? "\(Int(order.price * 0.4))" },
                            set: { broadcastPayoutAmounts[order.id] = $0 }
                        ))
                        .font(.system(size: 12, weight: .bold))
                        .keyboardType(.numberPad)
                    }
                    .padding(8)
                    .background(Color.bgInput)
                    .cornerRadius(8)
                    .frame(width: 130)
                    
                    Button(action: {
                        let defaultAmt = order.price * 0.4
                        let amt = Double(broadcastPayoutAmounts[order.id] ?? "\(Int(defaultAmt))") ?? defaultAmt
                        broadcastOrder(orderId: order.id, amount: amt)
                    }) {
                        HStack(spacing: 4) {
                            if isBroadcastingId == order.id {
                                ProgressView().tint(.white)
                            } else {
                                Image(systemName: "bolt.fill")
                            }
                            Text("Broadcast ⚡")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(Color.orange)
                        .cornerRadius(8)
                    }
                    .disabled(isBroadcastingId == order.id)
                }
            }
            
            // Direct Assignment Control
            VStack(alignment: .leading, spacing: 8) {
                Text("OPTION B: DIRECT SPECIALIST ASSIGNMENT")
                    .font(.system(size: 9, weight: .black))
                    .foregroundColor(.textMuted)
                
                HStack(spacing: 8) {
                    Menu {
                        Button("Select Specialist...") {
                            selectedFreelancerForOrder[order.id] = ""
                        }
                        ForEach(viewModel.freelancers) { f in
                            Button("\(f.name) (\(f.email))") {
                                selectedFreelancerForOrder[order.id] = f.idVal
                            }
                        }
                    } label: {
                        let currentId = selectedFreelancerForOrder[order.id] ?? order.assignedFreelancer?.idVal ?? ""
                        let matched = viewModel.freelancers.first { $0.idVal == currentId }
                        let displayName = matched?.name ?? order.assignedFreelancer?.name ?? "Select Specialist..."
                        HStack {
                            Text(displayName)
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.textDark)
                                .lineLimit(1)
                            Spacer()
                            Image(systemName: "chevron.down")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        .padding(8)
                        .background(Color.bgInput)
                        .cornerRadius(8)
                    }
                    
                    Button(action: {
                        if let fid = selectedFreelancerForOrder[order.id], !fid.isEmpty {
                            assignFreelancer(orderId: order.id, freelancerId: fid)
                        }
                    }) {
                        Text("Assign")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(Color.blue)
                            .cornerRadius(8)
                    }
                }
            }
            
            // Assigned Specialist Status & Payout Approval
            if let fl = order.assignedFreelancer {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Assigned: \(fl.name)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textDark)
                        if let payout = order.freelancerPayout {
                            Text("Payout: ₹\(Int(payout))")
                                .font(.system(size: 10))
                                .foregroundColor(.green)
                        }
                    }
                    Spacer()
                    
                    Button(action: {
                        approvePayout(orderId: order.id)
                    }) {
                        Text("Approve Payout")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Color.green)
                            .cornerRadius(6)
                    }
                    
                    Button(action: {
                        assignFreelancer(orderId: order.id, freelancerId: nil)
                    }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.red)
                    }
                }
                .padding(8)
                .background(Color.green.opacity(0.08))
                .cornerRadius(8)
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - SubTab 2: Registrations
    private var registrationsSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Search & Filter bar
            HStack {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search specialists...", text: $searchQuery)
                        .font(.system(size: 12))
                }
                .padding(10)
                .background(Color.white)
                .cornerRadius(10)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                
                Picker("Status", selection: $statusFilter) {
                    Text("All").tag("All")
                    Text("Approved").tag("Approved")
                    Text("Pending").tag("Pending")
                    Text("Rejected").tag("Rejected")
                }
                .pickerStyle(.menu)
                .padding(6)
                .background(Color.white)
                .cornerRadius(10)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
            }
            
            let filteredApplicants = applicants.filter { app in
                let q = searchQuery.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
                let matchesStatus = statusFilter == "All" || (app.verificationStatus ?? "Pending").lowercased() == statusFilter.lowercased()
                if !matchesStatus { return false }
                if q.isEmpty { return true }
                return "\(app.name) \(app.email) \(app.phone ?? "") \(app.panCard ?? "")".lowercased().contains(q)
            }
            
            if isLoadingApplicants {
                ProgressView().frame(maxWidth: .infinity).padding(30)
            } else if filteredApplicants.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "person.crop.rectangle.badge.plus")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No freelancer registrations found.")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
                .background(Color.white)
                .cornerRadius(16)
            } else {
                ForEach(filteredApplicants) { app in
                    applicantCard(app: app)
                }
            }
        }
    }
    
    private func applicantCard(app: FreelancerApplicant) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Circle()
                    .fill(Color.orange.opacity(0.15))
                    .frame(width: 40, height: 40)
                    .overlay(
                        Text(String(app.name.prefix(1)).uppercased())
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(.orange)
                    )
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.name)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    Text("\(app.email) • \(app.phone ?? "No phone")")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                Spacer()
                
                let st = app.verificationStatus ?? "Pending"
                Text(st.uppercased())
                    .font(.system(size: 8, weight: .black))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .foregroundColor(statusColor(st))
                    .background(statusColor(st).opacity(0.12))
                    .cornerRadius(6)
            }
            
            if let skills = app.skills, !skills.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(skills, id: \.self) { sk in
                            Text(sk)
                                .font(.system(size: 10, weight: .bold))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Color.blue.opacity(0.1))
                                .foregroundColor(.blue)
                                .cornerRadius(6)
                        }
                    }
                }
            }
            
            Divider().background(Color.borderLight)
            
            HStack(spacing: 8) {
                Button {
                    selectedApplicantForView = app
                } label: {
                    Text("View Profile")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.bgInput)
                        .cornerRadius(6)
                }
                
                Button {
                    startEditApplicant(app: app)
                } label: {
                    Text("Edit")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.blue)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(6)
                }
                
                Spacer()
                
                Button {
                    updateStatus(appId: app.id, status: "Approved")
                } label: {
                    Text("Approve")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.green)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.green.opacity(0.1))
                        .cornerRadius(6)
                }
                
                Button {
                    updateStatus(appId: app.id, status: "Rejected")
                } label: {
                    Text("Reject")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.red)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(6)
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - SubTab 3: Payouts Ledger
    private var payoutsSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "indianrupeesign.circle.fill")
                    .foregroundColor(.green)
                Text("FREELANCER PAYOUT SETTLEMENTS")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
                Button(action: { loadPayouts() }) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                }
            }
            
            if isLoadingPayouts {
                ProgressView().frame(maxWidth: .infinity).padding(30)
            } else if payoutRequests.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "creditcard")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No freelance payouts recorded")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
                .background(Color.white)
                .cornerRadius(16)
            } else {
                ForEach(payoutRequests) { pay in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(pay.orderTitle ?? "Service Payout")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Specialist: \(pay.freelancerName ?? "Contractor") • ₹\(Int(pay.amount))")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        if pay.status.lowercased() == "paid" {
                            Text("PAID")
                                .font(.system(size: 8, weight: .black))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .foregroundColor(.green)
                                .background(Color.green.opacity(0.12))
                                .cornerRadius(6)
                        } else {
                            Button(action: { payoutToSettle = pay }) {
                                Text("Settle Payout")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(Color.orange)
                                    .cornerRadius(6)
                            }
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - SubTab 4: Live Attendance Tracking
    private var liveAttendanceSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Circle().fill(Color.green).frame(width: 8, height: 8)
                Text("REAL-TIME SPECIALIST SESSIONS")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
                Button(action: { loadLiveAttendance() }) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                }
            }
            
            if isLoadingLive {
                ProgressView().frame(maxWidth: .infinity).padding(30)
            } else if liveSessions.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "clock")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No specialists currently clocked in.")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
                .background(Color.white)
                .cornerRadius(16)
            } else {
                ForEach(liveSessions) { sess in
                    HStack {
                        Circle()
                            .fill(sess.isClockedIn ? Color.green : Color.gray)
                            .frame(width: 10, height: 10)
                        
                        VStack(alignment: .leading, spacing: 3) {
                            Text(sess.name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(sess.isClockedIn ? "Clocked in: \(sess.clockInAt ?? "Active")" : "Offline")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        Text("\(sess.trackedMinutes) mins")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.blue)
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Sheets
    private func applicantDetailSheet(app: FreelancerApplicant) -> some View {
        NavigationView {
            Form {
                Section("Personal & Contact Details") {
                    LabeledContent("Name", value: app.name)
                    LabeledContent("Email", value: app.email)
                    LabeledContent("Phone", value: app.phone ?? "N/A")
                    LabeledContent("PAN Card", value: app.panCard ?? "N/A")
                    LabeledContent("Experience", value: "\(app.yearsOfExperience ?? 0) Years")
                }
                
                Section("Bank Account Details") {
                    LabeledContent("Bank Name", value: app.bankDetails?.bankName ?? "N/A")
                    LabeledContent("Account No", value: app.bankDetails?.accountNumber ?? "N/A")
                    LabeledContent("IFSC Code", value: app.bankDetails?.ifscCode ?? "N/A")
                    LabeledContent("Account Name", value: app.bankDetails?.accountName ?? "N/A")
                }
                
                if let resume = app.resumeUrl, !resume.isEmpty, let url = URL(string: resume) {
                    Section("Resume & Portfolio") {
                        Link(destination: url) {
                            Label("Open Resume / Credentials Document", systemImage: "doc.text.fill")
                                .foregroundColor(.blue)
                        }
                    }
                }
            }
            .navigationTitle("Specialist Profile")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { selectedApplicantForView = nil }
                }
            }
        }
    }
    
    private func applicantEditSheet(app: FreelancerApplicant) -> some View {
        NavigationView {
            Form {
                Section("Personal Details") {
                    TextField("Name", text: $editName)
                    TextField("Email", text: $editEmail)
                    TextField("Phone", text: $editPhone)
                    TextField("PAN Card", text: $editPan)
                    TextField("Years of Experience", text: $editExp)
                }
                
                Section("Bank Details") {
                    TextField("Bank Name", text: $editBankName)
                    TextField("Account Number", text: $editAccountNo)
                    TextField("IFSC Code", text: $editIfsc)
                }
            }
            .navigationTitle("Edit Specialist")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { applicantToEdit = nil }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") {
                        applicantToEdit = nil
                        viewModel.toastMessage = "Specialist details updated!"
                    }
                }
            }
        }
    }
    
    private func settlePayoutSheet(pay: FreelancerPayoutItem) -> some View {
        NavigationView {
            Form {
                Section("Payout Details") {
                    LabeledContent("Specialist", value: pay.freelancerName ?? "Contractor")
                    LabeledContent("Order", value: pay.orderTitle ?? "Service")
                    LabeledContent("Amount", value: "₹\(Int(pay.amount))")
                }
                
                Section("Settlement Information") {
                    Picker("Payment Method", selection: $settleMethod) {
                        Text("NEFT").tag("NEFT")
                        Text("UPI").tag("UPI")
                        Text("RTGS").tag("RTGS")
                        Text("IMPS").tag("IMPS")
                    }
                    TextField("Transaction Reference / UTR Number", text: $settleTxnRef)
                    TextField("Notes / Ledger memo", text: $settleNotes)
                }
            }
            .navigationTitle("Settle Payout")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { payoutToSettle = nil }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Confirm Settlement") {
                        settlePayout(payoutId: pay.id)
                    }
                    .disabled(settleTxnRef.isEmpty || isSettling)
                }
            }
        }
    }
    
    // MARK: - Actions
    private func loadSubTabData(tab: FreelancerSubTab) {
        switch tab {
        case .broadcast:
            break
        case .registrations:
            loadApplicants()
        case .payouts:
            loadPayouts()
        case .liveAttendance:
            loadLiveAttendance()
        }
    }
    
    private func loadApplicants() {
        isLoadingApplicants = true
        Task {
            do {
                applicants = try await NetworkManager.shared.getFreelancerApplicants()
            } catch {
                print("Failed to load applicants: \(error)")
            }
            isLoadingApplicants = false
        }
    }
    
    private func loadPayouts() {
        isLoadingPayouts = true
        Task {
            do {
                payoutRequests = try await NetworkManager.shared.getAdminFreelancerPayouts()
            } catch {
                print("Failed to load payouts: \(error)")
            }
            isLoadingPayouts = false
        }
    }
    
    private func loadLiveAttendance() {
        isLoadingLive = true
        Task {
            do {
                let res = try await NetworkManager.shared.getAttendanceSummary()
                liveSessions = res.items ?? []
            } catch {
                print("Failed to load live sessions: \(error)")
            }
            isLoadingLive = false
        }
    }
    
    private func broadcastOrder(orderId: String, amount: Double) {
        isBroadcastingId = orderId
        Task {
            do {
                _ = try await NetworkManager.shared.broadcastFreelancerOrder(orderId: orderId, payout: amount)
                viewModel.toastMessage = "Order broadcasted with ₹\(Int(amount)) payout budget!"
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
            }
            isBroadcastingId = nil
        }
    }
    
    private func assignFreelancer(orderId: String, freelancerId: String?) {
        Task {
            do {
                _ = try await NetworkManager.shared.assignFreelancerOrder(orderId: orderId, freelancerId: freelancerId)
                viewModel.toastMessage = freelancerId == nil ? "Assignment removed" : "Specialist assigned directly!"
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    private func approvePayout(orderId: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.approveFreelancerPayout(orderId: orderId)
                viewModel.toastMessage = "Work verified and payout released!"
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    private func updateStatus(appId: String, status: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.updateFreelancerApplicantStatus(id: appId, status: status)
                viewModel.toastMessage = "Specialist status updated to \(status)!"
                loadApplicants()
            } catch {
                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    private func startEditApplicant(app: FreelancerApplicant) {
        applicantToEdit = app
        editName = app.name
        editEmail = app.email
        editPhone = app.phone ?? ""
        editPan = app.panCard ?? ""
        editExp = "\(app.yearsOfExperience ?? 0)"
        editBankName = app.bankDetails?.bankName ?? ""
        editAccountNo = app.bankDetails?.accountNumber ?? ""
        editIfsc = app.bankDetails?.ifscCode ?? ""
    }
    
    private func settlePayout(payoutId: String) {
        isSettling = true
        Task {
            do {
                _ = try await NetworkManager.shared.settleFreelancerPayout(
                    id: payoutId,
                    method: settleMethod,
                    transactionRef: settleTxnRef,
                    notes: settleNotes
                )
                viewModel.toastMessage = "Payout settled successfully!"
                payoutToSettle = nil
                loadPayouts()
            } catch {
                viewModel.toastMessage = "Settlement failed: \(error.localizedDescription)"
            }
            isSettling = false
        }
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "approved", "paid": return .green
        case "rejected", "failed": return .red
        default: return .orange
        }
    }
}
