import SwiftUI

struct AdminComplianceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var viewMode: ComplianceViewMode = .calendar
    @State private var activeCategory: String = "Dashboard"
    @State private var searchQuery: String = ""
    @State private var currentMonth: Int = Calendar.current.component(.month, from: Date()) - 1
    @State private var currentYear: Int = Calendar.current.component(.year, from: Date())
    
    @State private var isTaskSheetOpen: Bool = false
    @State private var selectedTaskToEdit: ComplianceResponse? = nil
    @State private var prefillClientName: String? = nil
    @State private var prefillMonth: String? = nil
    
    enum ComplianceViewMode: String, CaseIterable {
        case calendar = "Calendar"
        case matrix = "Matrix"
    }
    
    private let categories = ["Dashboard", "GST", "MCA", "DIN KYC", "TDS/TCS", "Income Tax", "Adv Tax", "ESI", "PF", "PT", "Notices"]
    private let monthsShort = ["APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC", "JAN", "FEB", "MAR"]
    private let fullMonths = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("STATUTORY DEADLINES & AUDITS • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Compliance Hub")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Track statutory deadlines, regulatory returns, MCA filings, and client tax updates across portfolios.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 20/255, blue: 45/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // View Mode Switcher + Action Buttons
                VStack(spacing: 12) {
                    HStack {
                        // Calendar vs Matrix Toggle
                        HStack(spacing: 4) {
                            ForEach(ComplianceViewMode.allCases, id: \.self) { mode in
                                let isSelected = viewMode == mode
                                Button(action: { viewMode = mode }) {
                                    HStack(spacing: 5) {
                                        Image(systemName: mode == .calendar ? "calendar" : "tablecells")
                                        Text(mode.rawValue)
                                    }
                                    .font(.system(size: 12, weight: .bold))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSelected ? Color.indigoCustom : Color.white)
                                    .cornerRadius(10)
                                    .shadow(color: isSelected ? Color.indigoCustom.opacity(0.3) : Color.clear, radius: 4, y: 2)
                                }
                            }
                        }
                        
                        Spacer()
                        
                        // New Task Button
                        Button(action: {
                            selectedTaskToEdit = nil
                            prefillClientName = nil
                            prefillMonth = nil
                            isTaskSheetOpen = true
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "plus")
                                Text("New Task")
                            }
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(Color.indigoCustom)
                            .cornerRadius(10)
                            .shadow(color: Color.indigoCustom.opacity(0.3), radius: 4, y: 2)
                        }
                    }
                    
                    // Category Filter Scroll
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(categories, id: \.self) { cat in
                                let isSelected = activeCategory == cat
                                Button(action: { activeCategory = cat }) {
                                    Text(cat.uppercased())
                                        .font(.system(size: 10, weight: .black))
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 6)
                                        .foregroundColor(isSelected ? .white : Color(red: 80/255, green: 95/255, blue: 115/255))
                                        .background(isSelected ? Color.indigoCustom : Color.white)
                                        .cornerRadius(8)
                                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(isSelected ? Color.indigoCustom : Color.borderLight, lineWidth: 1))
                                }
                            }
                        }
                    }
                    
                    // Search Bar
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.textMuted)
                        TextField("Search client or task...", text: $searchQuery)
                            .font(.system(size: 13))
                        if !searchQuery.isEmpty {
                            Button(action: { searchQuery = "" }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.textMuted)
                            }
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // Content Views
                VStack {
                    if viewMode == .calendar {
                        calendarView
                    } else {
                        matrixView
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(isPresented: $isTaskSheetOpen) {
            ComplianceTaskSheet(
                taskToEdit: selectedTaskToEdit,
                prefillClientName: prefillClientName,
                prefillMonth: prefillMonth,
                clients: viewModel.users,
                onSave: { payload in
                    Task {
                        do {
                            if let editId = selectedTaskToEdit?.idVal {
                                _ = try await NetworkManager.shared.updateComplianceTask(id: editId, payload: payload)
                                viewModel.toastMessage = "Compliance task updated"
                            } else {
                                _ = try await NetworkManager.shared.createComplianceTask(payload: payload)
                                viewModel.toastMessage = "New compliance task scheduled"
                            }
                            viewModel.syncDashboardData()
                        } catch {
                            viewModel.toastMessage = "Error: \(error.localizedDescription)"
                        }
                    }
                },
                onDelete: { id in
                    Task {
                        do {
                            _ = try await NetworkManager.shared.deleteComplianceTask(id: id)
                            viewModel.toastMessage = "Compliance task deleted"
                            viewModel.syncDashboardData()
                        } catch {
                            viewModel.toastMessage = "Error: \(error.localizedDescription)"
                        }
                    }
                }
            )
        }
    }
    
    // MARK: - Filtered Records
    private var filteredRecords: [ComplianceResponse] {
        viewModel.complianceRecords.filter { r in
            let matchesSearch = searchQuery.isEmpty ||
                r.clientName.localizedCaseInsensitiveContains(searchQuery) ||
                r.taskName.localizedCaseInsensitiveContains(searchQuery)
            let matchesCategory = activeCategory == "Dashboard" || r.category == activeCategory
            return matchesSearch && matchesCategory
        }
    }
    
    // MARK: - Calendar View
    private var calendarView: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Month Switcher
            HStack {
                Text("\(fullMonths[currentMonth]) \(String(currentYear))")
                    .font(.system(size: 16, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                HStack(spacing: 8) {
                    Button(action: {
                        if currentMonth == 0 {
                            currentMonth = 11
                            currentYear -= 1
                        } else {
                            currentMonth -= 1
                        }
                    }) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                            .frame(width: 32, height: 32)
                            .background(Color.white)
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                    }
                    
                    Button(action: {
                        if currentMonth == 11 {
                            currentMonth = 0
                            currentYear += 1
                        } else {
                            currentMonth += 1
                        }
                    }) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                            .frame(width: 32, height: 32)
                            .background(Color.white)
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
            }
            
            // Monthly Tasks List
            if filteredRecords.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "calendar.badge.clock")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No compliance tasks recorded for this period")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
            } else {
                ForEach(filteredRecords) { r in
                    ComplianceTaskCardView(record: r) {
                        selectedTaskToEdit = r
                        isTaskSheetOpen = true
                    } onQuickStatus: { newStatus in
                        viewModel.updateComplianceStatus(id: r.idVal, status: newStatus)
                    }
                }
            }
        }
    }
    
    // MARK: - Matrix View
    private var matrixView: some View {
        VStack(alignment: .leading, spacing: 14) {
            let uniqueClients = Array(Set(viewModel.complianceRecords.map { $0.clientName })).sorted()
            
            if uniqueClients.isEmpty {
                Text("No client compliance records found.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(.vertical, 20)
            } else {
                ForEach(uniqueClients, id: \.self) { client in
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Circle()
                                .fill(Color.indigoCustom.opacity(0.12))
                                .frame(width: 32, height: 32)
                                .overlay(
                                    Text(String(client.prefix(1)).uppercased())
                                        .font(.system(size: 12, weight: .black))
                                        .foregroundColor(.indigoCustom)
                                )
                            Text(client)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Spacer()
                        }
                        
                        Divider().background(Color.borderLight)
                        
                        // Scrollable Month Status Chips
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 6) {
                                ForEach(monthsShort, id: \.self) { m in
                                    let match = viewModel.complianceRecords.first { $0.clientName == client && $0.periodMonth.uppercased() == m && (activeCategory == "Dashboard" || $0.category == activeCategory) }
                                    
                                    if let rec = match {
                                        Button(action: {
                                            selectedTaskToEdit = rec
                                            isTaskSheetOpen = true
                                        }) {
                                            VStack(spacing: 2) {
                                                Text(m)
                                                    .font(.system(size: 8, weight: .black))
                                                    .foregroundColor(.textMuted)
                                                Text(rec.status.uppercased())
                                                    .font(.system(size: 8, weight: .bold))
                                                    .foregroundColor(statusTextColor(rec.status))
                                            }
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .background(statusBgColor(rec.status))
                                            .cornerRadius(6)
                                            .overlay(RoundedRectangle(cornerRadius: 6).stroke(statusBorderColor(rec.status), lineWidth: 1))
                                        }
                                    } else {
                                        Button(action: {
                                            selectedTaskToEdit = nil
                                            prefillClientName = client
                                            prefillMonth = m
                                            isTaskSheetOpen = true
                                        }) {
                                            VStack(spacing: 2) {
                                                Text(m)
                                                    .font(.system(size: 8, weight: .black))
                                                    .foregroundColor(.textMuted)
                                                Text("+")
                                                    .font(.system(size: 9, weight: .bold))
                                                    .foregroundColor(.indigoCustom)
                                            }
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .background(Color.bgLight)
                                            .cornerRadius(6)
                                        }
                                    }
                                }
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
    
    private func statusTextColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "filed": return .green
        case "late": return .orange
        case "missed": return .red
        default: return .blue
        }
    }
    
    private func statusBgColor(_ status: String) -> Color {
        statusTextColor(status).opacity(0.12)
    }
    
    private func statusBorderColor(_ status: String) -> Color {
        statusTextColor(status).opacity(0.25)
    }
}

// MARK: - Compliance Task Card Subview
struct ComplianceTaskCardView: View {
    let record: ComplianceResponse
    let onInspect: () -> Void
    let onQuickStatus: (String) -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(record.category.uppercased())
                            .font(.system(size: 8, weight: .black))
                            .foregroundColor(.indigoCustom)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.indigoCustom.opacity(0.1))
                            .cornerRadius(4)
                        Text(record.periodMonth)
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                    Text(record.taskName)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    Text("Client: \(record.clientName)")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                Spacer()
                
                Menu {
                    ForEach(["Pending", "Filed", "Late", "Missed"], id: \.self) { st in
                        Button(st) {
                            onQuickStatus(st)
                        }
                    }
                } label: {
                    Text(record.status.uppercased())
                        .font(.system(size: 9, weight: .black))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .foregroundColor(statusColor(record.status))
                        .background(statusColor(record.status).opacity(0.12))
                        .cornerRadius(6)
                }
            }
            
            if !record.notes.isEmpty {
                Text("Notes: \(record.notes)")
                    .font(.system(size: 10))
                    .foregroundColor(.textMuted)
                    .lineLimit(2)
            }
            
            Divider().background(Color.borderLight)
            
            HStack {
                Text("Due: \(record.dueDate.prefix(10))")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.textMuted)
                Spacer()
                Button(action: onInspect) {
                    HStack(spacing: 4) {
                        Text("Edit Details")
                        Image(systemName: "pencil")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.indigoCustom)
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "filed": return .green
        case "late": return .orange
        case "missed": return .red
        default: return .blue
        }
    }
}

// MARK: - Compliance Task Sheet
struct ComplianceTaskSheet: View {
    let taskToEdit: ComplianceResponse?
    let prefillClientName: String?
    let prefillMonth: String?
    let clients: [UserResponse]
    let onSave: ([String: AnyCodable]) -> Void
    let onDelete: (String) -> Void
    
    @Environment(\.presentationMode) var presentationMode
    
    @State private var clientName: String = ""
    @State private var category: String = "GST"
    @State private var taskName: String = ""
    @State private var dueDate: Date = Date()
    @State private var periodMonth: String = "AUG"
    @State private var periodYear: String = "\(Calendar.current.component(.year, from: Date()))"
    @State private var status: String = "Pending"
    @State private var repeatFrequency: String = "None"
    @State private var sendBroadcast: Bool = true
    @State private var notes: String = ""
    
    private let categories = ["GST", "MCA", "DIN KYC", "TDS/TCS", "Income Tax", "Adv Tax", "ESI", "PF", "PT", "Notices"]
    private let months = ["APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC", "JAN", "FEB", "MAR"]
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("CLIENT & CLASSIFICATION").font(.system(size: 10, weight: .black))) {
                    TextField("Client Name (Leave blank for All Clients)", text: $clientName)
                        .font(.system(size: 13))
                    
                    Picker("Category", selection: $category) {
                        ForEach(categories, id: \.self) { cat in
                            Text(cat).tag(cat)
                        }
                    }
                    
                    TextField("Filing / Task Name *", text: $taskName)
                        .font(.system(size: 13))
                }
                
                Section(header: Text("STATUTORY SCHEDULE").font(.system(size: 10, weight: .black))) {
                    DatePicker("Statutory Due Date", selection: $dueDate, displayedComponents: .date)
                        .font(.system(size: 13))
                    
                    Picker("Period Month", selection: $periodMonth) {
                        ForEach(months, id: \.self) { m in
                            Text(m).tag(m)
                        }
                    }
                    
                    TextField("Period Year", text: $periodYear)
                        .font(.system(size: 13))
                        .keyboardType(.numberPad)
                }
                
                Section(header: Text("STATUS & AUTOMATION").font(.system(size: 10, weight: .black))) {
                    Picker("Filing Status", selection: $status) {
                        ForEach(["Pending", "Filed", "Late", "Missed"], id: \.self) { st in
                            Text(st).tag(st)
                        }
                    }
                    
                    Picker("Repeat Schedule", selection: $repeatFrequency) {
                        Text("One-Time Only").tag("None")
                        Text("Monthly").tag("Monthly")
                        Text("Quarterly").tag("Quarterly")
                    }
                    
                    if taskToEdit == nil {
                        Toggle("Broadcast Deadline Push & Email", isOn: $sendBroadcast)
                            .font(.system(size: 13))
                    }
                    
                    TextField("Filing Notes / Reference ARN", text: $notes)
                        .font(.system(size: 13))
                }
                
                if let t = taskToEdit {
                    Section {
                        Button(role: .destructive, action: {
                            onDelete(t.idVal)
                            presentationMode.wrappedValue.dismiss()
                        }) {
                            HStack {
                                Spacer()
                                Text("Delete Task")
                                    .font(.system(size: 13, weight: .bold))
                                Spacer()
                            }
                        }
                    }
                }
            }
            .navigationTitle(taskToEdit == nil ? "New Compliance" : "Edit Compliance")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { presentationMode.wrappedValue.dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(taskToEdit == nil ? "Create" : "Save") {
                        let formatter = DateFormatter()
                        formatter.dateFormat = "yyyy-MM-dd"
                        let dateStr = formatter.string(from: dueDate)
                        
                        let payload: [String: AnyCodable] = [
                            "clientName": AnyCodable(clientName),
                            "category": AnyCodable(category),
                            "taskName": AnyCodable(taskName),
                            "dueDate": AnyCodable(dateStr),
                            "periodMonth": AnyCodable(periodMonth),
                            "periodYear": AnyCodable(periodYear),
                            "status": AnyCodable(status),
                            "repeatFrequency": AnyCodable(repeatFrequency),
                            "sendBroadcast": AnyCodable(sendBroadcast),
                            "notes": AnyCodable(notes)
                        ]
                        onSave(payload)
                        presentationMode.wrappedValue.dismiss()
                    }
                    .font(.system(size: 13, weight: .black))
                    .disabled(taskName.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .onAppear {
                if let t = taskToEdit {
                    clientName = t.clientName
                    category = t.category
                    taskName = t.taskName
                    periodMonth = t.periodMonth
                    periodYear = t.periodYear
                    status = t.status
                    notes = t.notes
                    let formatter = DateFormatter()
                    formatter.dateFormat = "yyyy-MM-dd"
                    if let d = formatter.date(from: String(t.dueDate.prefix(10))) {
                        dueDate = d
                    }
                } else {
                    if let c = prefillClientName { clientName = c }
                    if let m = prefillMonth { periodMonth = m }
                }
            }
        }
    }
}

extension Color {
    static let indigoCustom = Color(red: 79/255, green: 70/255, blue: 229/255)
}
