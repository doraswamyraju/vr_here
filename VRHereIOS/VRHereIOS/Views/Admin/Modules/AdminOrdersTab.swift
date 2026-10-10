import SwiftUI

struct AdminOrdersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var viewMode: OrderViewMode = .list
    @State private var selectedTab: OrderWorkspaceTab = .overview
    
    // Edit Commercials Draft
    @State private var draftPackageName = ""
    @State private var draftPrice = ""
    @State private var draftServiceName = ""
    
    // Assignment Selectors
    @State private var selectedPMId: String = ""
    @State private var selectedMakerId: String = ""
    @State private var selectedCheckerId: String = ""
    @State private var selectedEmployeeId: String = ""
    
    // Modals
    @State private var showDeleteConfirm = false
    @State private var showAddTaskModal = false
    @State private var showRaiseReqModal = false
    @State private var showAddInvoiceModal = false
    
    // Add Task Form
    @State private var newTaskTitle = ""
    @State private var newTaskCode = ""
    @State private var newTaskRole = "Maker"
    @State private var newTaskDescription = ""
    
    // Raise Requirement Form
    @State private var newReqTitle = ""
    @State private var newReqDescription = ""
    
    // Add Invoice Form
    @State private var newInvoiceNumber = ""
    @State private var newInvoiceAmount = ""
    @State private var newInvoiceStatus = "Draft"
    @State private var newInvoiceNotes = ""
    
    enum OrderViewMode: String, CaseIterable {
        case list = "List View"
        case kanban = "Board (Kanban)"
    }
    
    enum OrderWorkspaceTab: String, CaseIterable {
        case overview = "Overview"
        case workflow = "Workflow & Team"
        case tasks = "Tasks & Workbook"
        case requirements = "Requirements & Docs"
        case financials = "Commercials & Invoices"
    }

    var selectedOrder: OrderResponse? {
        viewModel.orders.first(where: { $0.id == viewModel.selectedOrderId })
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if let order = selectedOrder {
                    // --- 1:1 ORDER WORKSPACE DRILLDOWN ---
                    orderWorkspaceView(order: order)
                } else {
                    // --- MAIN ORDERS DIRECTORY & BOARD ---
                    ordersListView
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(isPresented: $showAddTaskModal) {
            addTaskSheet
        }
        .sheet(isPresented: $showRaiseReqModal) {
            raiseReqSheet
        }
        .sheet(isPresented: $showAddInvoiceModal) {
            addInvoiceSheet
        }
        .alert("Delete Order Project?", isPresented: $showDeleteConfirm) {
            Button("Cancel", role: .cancel) { }
            Button("Delete Permanently", role: .destructive) {
                if let order = selectedOrder {
                    viewModel.deleteOrder(orderId: order.id)
                }
            }
        } message: {
            Text("Are you sure you want to delete this order? All associated tasks, files, and records will be permanently removed.")
        }
    }

    // MARK: - Main Orders List & Kanban
    private var ordersListView: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header Console
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("OPERATIONS STUDIO • v1.1.8")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(.cyan)
                            .tracking(1.5)
                        Text("Order Control Center")
                            .font(.system(size: 24, weight: .black))
                            .foregroundColor(.white)
                    }
                    Spacer()
                    // View Mode Toggle
                    Picker("View Mode", selection: $viewMode) {
                        ForEach(OrderViewMode.allCases, id: \.self) { mode in
                            Text(mode.rawValue).tag(mode)
                        }
                    }
                    .pickerStyle(SegmentedPickerStyle())
                    .frame(width: 170)
                }
                
                Text("Manage project workflows, maker-checker handoffs, task workbooks, and client billing.")
                    .font(.system(size: 12))
                    .foregroundColor(.white.opacity(0.75))
            }
            .padding(20)
            .background(
                LinearGradient(colors: [Color.darkSlate, Color(red: 20/255, green: 30/255, blue: 55/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
            )
            .cornerRadius(24)
            .padding(.horizontal, 20)
            .padding(.top, 16)
            
            // Search Bar & Count
            HStack(spacing: 12) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search by client, email, phone, or service...", text: $searchQuery)
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
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
            }
            .padding(.horizontal, 20)
            
            // Status Chips
            let filterOptions = ["All", "Pending", "In Progress", "Pending Documents", "Documents Verified", "Completed"]
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(filterOptions, id: \.self) { opt in
                        let isSelected = viewModel.selectedOrderFilter.lowercased() == opt.lowercased()
                        Button(action: {
                            withAnimation(.spring()) {
                                viewModel.selectedOrderFilter = opt
                            }
                        }) {
                            Text(opt)
                                .font(.system(size: 11, weight: .bold))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 7)
                                .foregroundColor(isSelected ? .white : Color(red: 50/255, green: 65/255, blue: 85/255))
                                .background(isSelected ? Color.primaryRed : Color.white)
                                .cornerRadius(20)
                                .shadow(color: isSelected ? Color.primaryRed.opacity(0.25) : Color.black.opacity(0.02), radius: 4, y: 2)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 20)
                                        .stroke(isSelected ? Color.primaryRed : Color.borderLight, lineWidth: 1)
                                )
                        }
                    }
                }
                .padding(.horizontal, 20)
            }
            
            // Filtered Orders Data
            let filtered = viewModel.orders.filter { order in
                let q = searchQuery.lowercased()
                let matchesSearch = q.isEmpty ||
                    order.serviceName.lowercased().contains(q) ||
                    order.clientName.lowercased().contains(q) ||
                    order.email.lowercased().contains(q) ||
                    order.phone.lowercased().contains(q)
                
                let f = viewModel.selectedOrderFilter.lowercased()
                let matchesStatus: Bool
                if f == "all" {
                    matchesStatus = true
                } else if f == "pending" {
                    matchesStatus = order.status.lowercased() != "completed"
                } else if f == "completed" {
                    matchesStatus = order.status.lowercased() == "completed"
                } else {
                    matchesStatus = order.status.localizedCaseInsensitiveContains(viewModel.selectedOrderFilter)
                }
                return matchesSearch && matchesStatus
            }
            
            if viewMode == .list {
                // List View Layout
                VStack(spacing: 12) {
                    if filtered.isEmpty {
                        emptyStateView
                    } else {
                        ForEach(filtered) { order in
                            orderCardView(order: order)
                        }
                    }
                }
                .padding(.horizontal, 20)
            } else {
                // Kanban Board View Layout
                kanbanBoardView(orders: filtered)
            }
        }
    }

    // MARK: - Order Card (List View)
    private func orderCardView(order: OrderResponse) -> some View {
        Button(action: {
            withAnimation {
                openOrderWorkspace(order: order)
            }
        }) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(order.serviceName)
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.textDark)
                            .multilineTextAlignment(.leading)
                        Text("Client: \(order.clientName) • \(order.phone.isEmpty ? order.email : order.phone)")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.textMuted)
                    }
                    Spacer()
                    
                    statusBadge(status: order.status)
                }
                
                Divider().background(Color.borderLight)
                
                HStack {
                    HStack(spacing: 4) {
                        Image(systemName: "indianrupeesign.circle.fill")
                            .foregroundColor(.green)
                            .font(.system(size: 12))
                        Text("₹\(Int(order.price))")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Text("(\(order.paymentStatus.isEmpty ? "Pending" : order.paymentStatus))")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(order.paymentStatus.lowercased() == "paid" ? .green : .orange)
                    }
                    
                    Spacer()
                    
                    HStack(spacing: 6) {
                        Image(systemName: "person.crop.circle")
                            .font(.system(size: 12))
                            .foregroundColor(.indigo)
                        Text(order.assignedEmployee?.name ?? "Unassigned")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(order.assignedEmployee != nil ? .indigo : .orange)
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 3)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        }
        .buttonStyle(PlainButtonStyle())
    }

    // MARK: - Kanban Board View
    private func kanbanBoardView(orders: [OrderResponse]) -> some View {
        let columns = ["Pending", "In Progress", "Pending Documents", "Documents Verified", "Completed"]
        
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(alignment: .top, spacing: 16) {
                ForEach(columns, id: \.self) { col in
                    let colOrders = orders.filter { o in
                        if col == "Pending" {
                            return o.status.lowercased() == "pending" || o.status.isEmpty
                        }
                        return o.status.lowercased() == col.lowercased()
                    }
                    
                    VStack(alignment: .leading, spacing: 12) {
                        // Column Header
                        HStack {
                            Text(col)
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(.textDark)
                            Spacer()
                            Text("\(colOrders.count)")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 2)
                                .background(statusColor(col))
                                .cornerRadius(10)
                        }
                        .padding(.horizontal, 4)
                        
                        // Cards
                        ScrollView(.vertical, showsIndicators: false) {
                            VStack(spacing: 10) {
                                ForEach(colOrders) { order in
                                    Button(action: { openOrderWorkspace(order: order) }) {
                                        VStack(alignment: .leading, spacing: 8) {
                                            Text(order.serviceName)
                                                .font(.system(size: 12, weight: .bold))
                                                .foregroundColor(.textDark)
                                                .lineLimit(2)
                                                .multilineTextAlignment(.leading)
                                            
                                            Text(order.clientName)
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                            
                                            HStack {
                                                Text("₹\(Int(order.price))")
                                                    .font(.system(size: 11, weight: .black))
                                                    .foregroundColor(.green)
                                                Spacer()
                                                Menu {
                                                    ForEach(columns, id: \.self) { targetStatus in
                                                        Button(targetStatus) {
                                                            viewModel.updateOrderStatus(orderId: order.id, status: targetStatus)
                                                        }
                                                    }
                                                } label: {
                                                    Image(systemName: "ellipsis.circle")
                                                        .foregroundColor(.textMuted)
                                                }
                                            }
                                        }
                                        .padding(12)
                                        .frame(width: 200, alignment: .leading)
                                        .background(Color.white)
                                        .cornerRadius(14)
                                        .shadow(color: Color.black.opacity(0.02), radius: 4, y: 2)
                                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                        }
                        .frame(maxHeight: 500)
                    }
                    .padding(12)
                    .frame(width: 224)
                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                    .cornerRadius(18)
                }
            }
            .padding(.horizontal, 20)
        }
    }

    // MARK: - Order Workspace Screen
    private func orderWorkspaceView(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            // Workspace Header Bar
            HStack {
                Button(action: { viewModel.selectedOrderId = "" }) {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.left")
                        Text("All Orders")
                    }
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.primaryRed)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.primaryRed.opacity(0.1))
                    .cornerRadius(10)
                }
                
                Spacer()
                
                // Status Stepper Dropdown
                Menu {
                    let statuses = ["Pending", "In Progress", "Pending Documents", "Documents Verified", "Completed"]
                    ForEach(statuses, id: \.self) { st in
                        Button(action: { viewModel.updateOrderStatus(orderId: order.id, status: st) }) {
                            HStack {
                                Text(st)
                                if order.status.lowercased() == st.lowercased() {
                                    Image(systemName: "checkmark")
                                }
                            }
                        }
                    }
                } label: {
                    HStack(spacing: 6) {
                        Text(order.status.uppercased())
                            .font(.system(size: 10, weight: .black))
                        Image(systemName: "chevron.down")
                            .font(.system(size: 9, weight: .black))
                    }
                    .foregroundColor(statusColor(order.status))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(statusColor(order.status).opacity(0.12))
                    .cornerRadius(10)
                }
                
                // Delete Project Action
                Button(action: { showDeleteConfirm = true }) {
                    Image(systemName: "trash")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.red)
                        .padding(8)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(10)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            
            // Project Title Header
            VStack(alignment: .leading, spacing: 4) {
                Text(order.serviceName)
                    .font(.system(size: 22, weight: .black))
                    .foregroundColor(.textDark)
                Text("Order ID: \(order.idVal) • Client: \(order.clientName)")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
            }
            .padding(.horizontal, 20)
            
            // Sub-Tabs Switcher Bar
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(OrderWorkspaceTab.allCases, id: \.self) { tab in
                        let isSelected = selectedTab == tab
                        Button(action: { selectedTab = tab }) {
                            Text(tab.rawValue)
                                .font(.system(size: 12, weight: .bold))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 8)
                                .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                .background(isSelected ? Color.darkSlate : Color.white)
                                .cornerRadius(12)
                                .shadow(color: isSelected ? Color.black.opacity(0.1) : Color.clear, radius: 4, y: 2)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(isSelected ? Color.darkSlate : Color.borderLight, lineWidth: 1)
                                )
                        }
                    }
                }
                .padding(.horizontal, 20)
            }
            
            // Tab View Body
            VStack {
                switch selectedTab {
                case .overview:
                    workspaceOverviewTab(order: order)
                case .workflow:
                    workspaceWorkflowTab(order: order)
                case .tasks:
                    workspaceTasksTab(order: order)
                case .requirements:
                    workspaceRequirementsTab(order: order)
                case .financials:
                    workspaceFinancialsTab(order: order)
                }
            }
            .padding(.horizontal, 20)
        }
    }

    // MARK: - Tab 1: Overview
    private func workspaceOverviewTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            // Client Contact Quick Actions
            VStack(alignment: .leading, spacing: 12) {
                Text("Client Contact & Communications")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                
                HStack(spacing: 10) {
                    if !order.phone.isEmpty {
                        Button(action: {
                            if let url = URL(string: "https://wa.me/\(order.phone.replacingOccurrences(of: "+", with: "").replacingOccurrences(of: " ", with: ""))") {
                                UIApplication.shared.open(url)
                            }
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "message.fill")
                                Text("WhatsApp")
                            }
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.vertical, 8)
                            .frame(maxWidth: .infinity)
                            .background(Color.green)
                            .cornerRadius(10)
                        }
                        
                        Button(action: {
                            if let url = URL(string: "tel://\(order.phone)") {
                                UIApplication.shared.open(url)
                            }
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "phone.fill")
                                Text("Call")
                            }
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.vertical, 8)
                            .frame(maxWidth: .infinity)
                            .background(Color.blue)
                            .cornerRadius(10)
                        }
                    }
                    
                    if !order.email.isEmpty {
                        Button(action: {
                            if let url = URL(string: "mailto:\(order.email)") {
                                UIApplication.shared.open(url)
                            }
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "envelope.fill")
                                Text("Email")
                            }
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.vertical, 8)
                            .frame(maxWidth: .infinity)
                            .background(Color.indigo)
                            .cornerRadius(10)
                        }
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            
            // Order Metrics Card
            VStack(alignment: .leading, spacing: 12) {
                Text("Project Milestones & Details")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                
                detailRow(title: "Client Name", value: order.clientName)
                detailRow(title: "Email Address", value: order.email)
                detailRow(title: "Phone Number", value: order.phone.isEmpty ? "N/A" : order.phone)
                detailRow(title: "Package Selected", value: order.packageName.isEmpty ? "Standard" : order.packageName)
                detailRow(title: "Order Amount", value: "₹\(Int(order.price))")
                detailRow(title: "Payment Status", value: order.paymentStatus.isEmpty ? "Pending" : order.paymentStatus)
                detailRow(title: "Payment Reference ID", value: order.paymentId.isEmpty ? "None" : order.paymentId)
                detailRow(title: "Created At", value: order.createdAt)
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        }
    }

    // MARK: - Tab 2: Workflow & Team Assignments
    private func workspaceWorkflowTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Maker-Checker & Management Workflow")
                .font(.system(size: 14, weight: .black))
                .foregroundColor(.textDark)
            
            // Assigned PM Selector
            VStack(alignment: .leading, spacing: 6) {
                Text("Assigned Project Manager (Lead)")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textMuted)
                
                Menu {
                    Button("Unassigned") { selectedPMId = "" }
                    ForEach(viewModel.employees) { emp in
                        Button(emp.name) { selectedPMId = emp.idVal }
                    }
                } label: {
                    HStack {
                        let name = viewModel.employees.first(where: { $0.idVal == selectedPMId })?.name ?? order.assignedProjectManager?.name ?? order.assignedEmployee?.name ?? "Select Project Manager"
                        Text(name)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                        Spacer()
                        Image(systemName: "chevron.up.chevron.down")
                            .foregroundColor(.textMuted)
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
            
            // Assigned Maker Selector
            VStack(alignment: .leading, spacing: 6) {
                Text("Assigned Maker (Preparer / Associate)")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textMuted)
                
                Menu {
                    Button("Unassigned") { selectedMakerId = "" }
                    ForEach(viewModel.employees) { emp in
                        Button(emp.name) { selectedMakerId = emp.idVal }
                    }
                } label: {
                    HStack {
                        let name = viewModel.employees.first(where: { $0.idVal == selectedMakerId })?.name ?? order.assignedMaker?.name ?? "Select Maker"
                        Text(name)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                        Spacer()
                        Image(systemName: "chevron.up.chevron.down")
                            .foregroundColor(.textMuted)
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
            
            // Assigned Checker Selector
            VStack(alignment: .leading, spacing: 6) {
                Text("Assigned Checker (Auditor / Reviewer)")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textMuted)
                
                Menu {
                    Button("Unassigned") { selectedCheckerId = "" }
                    ForEach(viewModel.employees) { emp in
                        Button(emp.name) { selectedCheckerId = emp.idVal }
                    }
                } label: {
                    HStack {
                        let name = viewModel.employees.first(where: { $0.idVal == selectedCheckerId })?.name ?? order.assignedChecker?.name ?? "Select Checker"
                        Text(name)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                        Spacer()
                        Image(systemName: "chevron.up.chevron.down")
                            .foregroundColor(.textMuted)
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
            
            // Save Assignments Button
            Button(action: {
                viewModel.updateOrderAssignments(
                    orderId: order.id,
                    employeeId: selectedPMId.isEmpty ? nil : selectedPMId,
                    makerId: selectedMakerId.isEmpty ? nil : selectedMakerId,
                    checkerId: selectedCheckerId.isEmpty ? nil : selectedCheckerId,
                    projectManagerId: selectedPMId.isEmpty ? nil : selectedPMId
                )
            }) {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                    Text("Save Team Assignments")
                }
                .font(.system(size: 13, weight: .bold))
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Color.indigo)
                .cornerRadius(14)
                .shadow(color: Color.indigo.opacity(0.3), radius: 6, y: 3)
            }
            .padding(.top, 8)
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        .onAppear {
            selectedPMId = order.assignedProjectManager?.idVal ?? order.assignedEmployee?.idVal ?? ""
            selectedMakerId = order.assignedMaker?.idVal ?? ""
            selectedCheckerId = order.assignedChecker?.idVal ?? ""
        }
    }

    // MARK: - Tab 3: Tasks & Workbook
    private func workspaceTasksTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Project Tasks & Milestones")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: { showAddTaskModal = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Add Task")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.primaryRed)
                    .cornerRadius(8)
                }
            }
            
            if order.tasks.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checklist")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No tasks added yet")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
            } else {
                ForEach(order.tasks) { task in
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(task.title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Code: \(task.taskCode.isEmpty ? "TASK" : task.taskCode) • Role: \(task.ownerRole)")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            Menu {
                                Button("Pending") { viewModel.updateTaskStatus(orderId: order.id, taskId: task.id, status: "Pending") }
                                Button("In Progress") { viewModel.updateTaskStatus(orderId: order.id, taskId: task.id, status: "In Progress") }
                                Button("Completed") { viewModel.updateTaskStatus(orderId: order.id, taskId: task.id, status: "Completed") }
                            } label: {
                                Text(task.status.uppercased())
                                    .font(.system(size: 8, weight: .black))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .foregroundColor(statusColor(task.status))
                                    .background(statusColor(task.status).opacity(0.12))
                                    .cornerRadius(6)
                            }
                        }
                        
                        if !task.description.isEmpty {
                            Text(task.description)
                                .font(.system(size: 11))
                                .foregroundColor(.textDark.opacity(0.8))
                        }
                        
                        // Subtasks
                        if !task.subtasks.isEmpty {
                            Divider().background(Color.borderLight)
                            VStack(alignment: .leading, spacing: 6) {
                                Text("SUBTASKS (\(task.subtasks.filter { $0.isCompleted }.count)/\(task.subtasks.count))")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(.textMuted)
                                
                                ForEach(task.subtasks) { sub in
                                    HStack {
                                        Button(action: {
                                            viewModel.updateSubtask(
                                                orderId: order.id,
                                                taskId: task.id,
                                                subtaskId: sub.id,
                                                isCompleted: !sub.isCompleted,
                                                status: !sub.isCompleted ? "Completed" : "Pending"
                                            )
                                        }) {
                                            Image(systemName: sub.isCompleted ? "checkmark.square.fill" : "square")
                                                .foregroundColor(sub.isCompleted ? .green : .textMuted)
                                        }
                                        
                                        Text(sub.title)
                                            .font(.system(size: 11, weight: sub.isCompleted ? .regular : .medium))
                                            .foregroundColor(sub.isCompleted ? .textMuted : .textDark)
                                            .strikethrough(sub.isCompleted)
                                        
                                        Spacer()
                                    }
                                }
                            }
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - Tab 4: Requirements & Documents
    private func workspaceRequirementsTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Required Documents & Checklist")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: { showRaiseReqModal = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Raise Requirement")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.primaryRed)
                    .cornerRadius(8)
                }
            }
            
            if order.customerRequirements.isEmpty && order.clientDocuments.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No requirements or documents attached")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
            } else {
                ForEach(order.customerRequirements) { req in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(req.title)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            if !req.description.isEmpty {
                                Text(req.description)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            if !req.uploadedDocumentUrl.isEmpty {
                                Link(destination: URL(string: req.uploadedDocumentUrl) ?? URL(string: "https://vrhere.in")!) {
                                    HStack(spacing: 4) {
                                        Image(systemName: "doc.fill")
                                        Text(req.uploadedDocumentName.isEmpty ? "View Uploaded File" : req.uploadedDocumentName)
                                    }
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.blue)
                                }
                            }
                        }
                        Spacer()
                        
                        // Status Switcher
                        Menu {
                            Button("Pending") { viewModel.updateRequirementStatus(orderId: order.id, requirementId: req.id, status: "Pending") }
                            Button("Uploaded") { viewModel.updateRequirementStatus(orderId: order.id, requirementId: req.id, status: "Uploaded") }
                            Button("Verified") { viewModel.updateRequirementStatus(orderId: order.id, requirementId: req.id, status: "Verified") }
                            Button("Rejected") { viewModel.updateRequirementStatus(orderId: order.id, requirementId: req.id, status: "Rejected") }
                        } label: {
                            Text(req.status.uppercased())
                                .font(.system(size: 8, weight: .black))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .foregroundColor(statusColor(req.status))
                                .background(statusColor(req.status).opacity(0.12))
                                .cornerRadius(6)
                        }
                        
                        Button(action: { viewModel.deleteRequirement(orderId: order.id, requirementId: req.id) }) {
                            Image(systemName: "trash")
                                .font(.system(size: 11))
                                .foregroundColor(.red.opacity(0.7))
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - Tab 5: Commercials & Invoices
    private func workspaceFinancialsTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            // Price & Package Editor Card
            VStack(alignment: .leading, spacing: 12) {
                Text("Commercial Package & Pricing")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Service Title")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                    TextField("Service Name", text: $draftServiceName)
                        .font(.system(size: 13))
                        .padding(10)
                        .background(Color.white)
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                }
                
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Package Name")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.textMuted)
                        TextField("e.g. Standard", text: $draftPackageName)
                            .font(.system(size: 13))
                            .padding(10)
                            .background(Color.white)
                            .cornerRadius(10)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Price (INR)")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.textMuted)
                        TextField("e.g. 4999", text: $draftPrice)
                            .font(.system(size: 13))
                            .keyboardType(.numberPad)
                            .padding(10)
                            .background(Color.white)
                            .cornerRadius(10)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
                
                Button(action: {
                    let p = Double(draftPrice) ?? order.price
                    viewModel.updateOrderCommercials(
                        orderId: order.id,
                        packageName: draftPackageName,
                        price: p,
                        serviceName: draftServiceName
                    )
                }) {
                    HStack {
                        Image(systemName: "square.and.arrow.down.fill")
                        Text("Update Commercial Details")
                    }
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.primaryRed)
                    .cornerRadius(12)
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
            .onAppear {
                draftServiceName = order.serviceName
                draftPackageName = order.packageName
                draftPrice = "\(Int(order.price))"
            }
            
            // Invoices Ledger
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Client Invoices & Billing")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                    Spacer()
                    Button(action: { showAddInvoiceModal = true }) {
                        HStack(spacing: 4) {
                            Image(systemName: "plus")
                            Text("Generate Invoice")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.green)
                        .cornerRadius(8)
                    }
                }
                
                if order.invoices.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "doc.plaintext")
                            .font(.system(size: 26))
                            .foregroundColor(.textMuted)
                        Text("No invoices generated yet")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(20)
                } else {
                    ForEach(order.invoices) { inv in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(inv.invoiceNumber)
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.textDark)
                                Text("Amount: ₹\(Int(inv.amount)) • Date: \(inv.createdAt)")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            Menu {
                                Button("Draft") { viewModel.updateInvoiceStatus(orderId: order.id, invoiceId: inv.id, status: "Draft") }
                                Button("Sent") { viewModel.updateInvoiceStatus(orderId: order.id, invoiceId: inv.id, status: "Sent") }
                                Button("Paid") { viewModel.updateInvoiceStatus(orderId: order.id, invoiceId: inv.id, status: "Paid") }
                                Button("Cancelled") { viewModel.updateInvoiceStatus(orderId: order.id, invoiceId: inv.id, status: "Cancelled") }
                            } label: {
                                Text(inv.status.uppercased())
                                    .font(.system(size: 8, weight: .black))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .foregroundColor(inv.status.lowercased() == "paid" ? .green : .orange)
                                    .background((inv.status.lowercased() == "paid" ? Color.green : Color.orange).opacity(0.12))
                                    .cornerRadius(6)
                            }
                        }
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(12)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        }
    }

    // MARK: - Modals / Sheets
    private var addTaskSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Task Details")) {
                    TextField("Task Title", text: $newTaskTitle)
                    TextField("Task Code (e.g. TSK-01)", text: $newTaskCode)
                    Picker("Role", selection: $newTaskRole) {
                        Text("Maker").tag("Maker")
                        Text("Checker").tag("Checker")
                        Text("Project Manager").tag("ProjectManager")
                    }
                    TextField("Task Description", text: $newTaskDescription)
                }
            }
            .navigationTitle("Add Project Task")
            .navigationBarItems(
                leading: Button("Cancel") { showAddTaskModal = false },
                trailing: Button("Save") {
                    if let order = selectedOrder, !newTaskTitle.isEmpty {
                        viewModel.addOrderTask(
                            orderId: order.id,
                            title: newTaskTitle,
                            taskCode: newTaskCode.isEmpty ? "TSK-\(Int.random(in: 100...999))" : newTaskCode,
                            description: newTaskDescription,
                            ownerRole: newTaskRole
                        ) { _ in
                            newTaskTitle = ""
                            newTaskDescription = ""
                            showAddTaskModal = false
                        }
                    }
                }
                .font(.headline)
                .disabled(newTaskTitle.isEmpty)
            )
        }
    }

    private var raiseReqSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Requirement Details")) {
                    TextField("Document / Detail Title", text: $newReqTitle)
                    TextField("Description & Instructions", text: $newReqDescription)
                }
            }
            .navigationTitle("Raise Requirement")
            .navigationBarItems(
                leading: Button("Cancel") { showRaiseReqModal = false },
                trailing: Button("Raise") {
                    if let order = selectedOrder, !newReqTitle.isEmpty {
                        viewModel.raiseRequirement(
                            orderId: order.id,
                            title: newReqTitle,
                            description: newReqDescription
                        ) { _ in
                            newReqTitle = ""
                            newReqDescription = ""
                            showRaiseReqModal = false
                        }
                    }
                }
                .font(.headline)
                .disabled(newReqTitle.isEmpty)
            )
        }
    }

    private var addInvoiceSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Invoice Information")) {
                    TextField("Invoice Number (e.g. INV-2026-001)", text: $newInvoiceNumber)
                    TextField("Amount in INR", text: $newInvoiceAmount)
                        .keyboardType(.numberPad)
                    Picker("Status", selection: $newInvoiceStatus) {
                        Text("Draft").tag("Draft")
                        Text("Sent").tag("Sent")
                        Text("Paid").tag("Paid")
                    }
                    TextField("Notes & Terms", text: $newInvoiceNotes)
                }
            }
            .navigationTitle("Generate Invoice")
            .navigationBarItems(
                leading: Button("Cancel") { showAddInvoiceModal = false },
                trailing: Button("Create") {
                    if let order = selectedOrder, let amt = Double(newInvoiceAmount), !newInvoiceNumber.isEmpty {
                        viewModel.addOrderInvoice(
                            orderId: order.id,
                            invoiceNumber: newInvoiceNumber,
                            amount: amt,
                            status: newInvoiceStatus,
                            notes: newInvoiceNotes.isEmpty ? nil : newInvoiceNotes
                        ) { _ in
                            newInvoiceNumber = ""
                            newInvoiceAmount = ""
                            showAddInvoiceModal = false
                        }
                    }
                }
                .font(.headline)
                .disabled(newInvoiceNumber.isEmpty || newInvoiceAmount.isEmpty)
            )
        }
    }

    private func openOrderWorkspace(order: OrderResponse) {
        viewModel.selectedOrderId = order.id
        selectedTab = .overview
    }

    private var emptyStateView: some View {
        VStack(spacing: 12) {
            Image(systemName: "folder.badge.questionmark")
                .font(.system(size: 40))
                .foregroundColor(.textMuted)
            Text("No matching orders found")
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(.textDark)
            Text("Try changing search filters or create a new order from Quick Actions.")
                .font(.system(size: 11))
                .foregroundColor(.textMuted)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }

    private func detailRow(title: String, value: String) -> some View {
        HStack {
            Text(title)
                .font(.system(size: 12))
                .foregroundColor(.textMuted)
            Spacer()
            Text(value)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.textDark)
                .multilineTextAlignment(.trailing)
        }
    }

    private func statusBadge(status: String) -> some View {
        Text(status.uppercased())
            .font(.system(size: 8, weight: .black))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .foregroundColor(statusColor(status))
            .background(statusColor(status).opacity(0.12))
            .cornerRadius(6)
    }

    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "completed", "verified", "paid":
            return .green
        case "in progress", "processing", "uploaded":
            return .blue
        case "pending documents", "documents verified":
            return .indigo
        case "pending", "draft":
            return .orange
        default:
            return .red
        }
    }
}
