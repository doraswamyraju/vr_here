import SwiftUI

struct AdminOrdersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var viewMode: OrderViewMode = .list
    @State private var selectedTab: OrderWorkspaceTab = .overview
    
    // Inline Name Editing
    @State private var isEditingName = false
    @State private var editNameValue = ""
    @State private var isSavingName = false
    
    // Assignment & Commercials
    @State private var draftStatus = ""
    @State private var draftPMId = ""
    @State private var draftMakerId = ""
    @State private var draftCheckerId = ""
    @State private var draftPrice = ""
    @State private var isSavingAssignments = false
    @State private var saveSuccessMessage = ""
    
    // Workspace Sub-Data
    @State private var orderPayments: [PaymentResponse] = []
    @State private var orderMilestones: [MilestoneHistoryResponse] = []
    @State private var orderTodos: [TodoResponse] = []
    @State private var workflowTickets: [WorkflowTicketResponse] = []
    @State private var itrAssessment: ITAssessmentResponse? = nil
    @State private var newTodoTitle = ""
    @State private var isLoadingSubData = false
    
    // Modals & Sheets
    @State private var showWorkflowTicketModal = false
    @State private var showMakeRecurringModal = false
    @State private var showAddTaskModal = false
    @State private var showRaiseReqModal = false
    @State private var showInvoiceAdjustModal = false
    @State private var showDeleteConfirm = false
    @State private var selectedInvoiceForPdf: OrderInvoice? = nil
    
    // Freelancer Panel States
    @State private var freelancerBroadcastPayout = ""
    @State private var selectedFreelancerId = ""
    @State private var directFreelancerPayout = ""
    @State private var isReassigningFreelancer = false
    
    // Balance Invoice Form (ITR / CA)
    @State private var balanceInvoiceAmount = ""
    @State private var balanceInvoiceDueDate = ""
    @State private var balanceInvoiceNotes = "Balance fees invoice raised by CA review."
    @State private var isRaisingBalanceInvoice = false
    
    // Workflow Ticket Form
    @State private var newTicketTitle = ""
    @State private var newTicketCategory = "General"
    @State private var newTicketPriority = "Medium"
    @State private var newTicketDesc = ""
    @State private var newTicketAssignee = ""
    @State private var isCreatingTicket = false
    
    // Add Task Form
    @State private var newTaskTitle = ""
    @State private var newTaskRole = "Maker"
    @State private var newTaskDesc = ""
    
    // Raise Requirement Form
    @State private var newReqTitle = ""
    @State private var newReqDesc = ""
    @State private var newReqRequired = true
    
    // Adjusted Invoice Form
    @State private var invPackageName = ""
    @State private var invAmount = ""
    @State private var invDueDate = ""
    @State private var invNotes = ""
    @State private var invAdjustConsultation = false
    @State private var invAdjustPrevious = false
    @State private var isInitiatingBilling = false
    
    enum OrderViewMode: String, CaseIterable {
        case list = "List View"
        case kanban = "Board (Kanban)"
    }
    
    enum OrderWorkspaceTab: String, CaseIterable {
        case overview = "Overview"
        case chat = "Chat"
        case tasks = "Tasks"
        case requirements = "Requirements"
        case workflowTickets = "Workflow Tickets"
        case invoices = "Invoices"
        case todo = "ToDo"
        case transactions = "Transactions"
        case activities = "Activities"
        case docs = "Docs"
    }
    
    var selectedOrder: OrderResponse? {
        viewModel.orders.first(where: { $0.id == viewModel.selectedOrderId })
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if let order = selectedOrder {
                    // --- 100% 1:1 ORDER WORKSPACE DRILLDOWN ---
                    orderWorkspaceView(order: order)
                } else {
                    // --- MAIN ORDERS DIRECTORY & BOARD ---
                    ordersDirectoryView
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(isPresented: $showWorkflowTicketModal) {
            raiseWorkflowTicketSheet
        }
        .sheet(isPresented: $showMakeRecurringModal) {
            makeRecurringSheet
        }
        .sheet(isPresented: $showAddTaskModal) {
            addTaskSheet
        }
        .sheet(isPresented: $showRaiseReqModal) {
            raiseRequirementSheet
        }
        .sheet(isPresented: $showInvoiceAdjustModal) {
            initiateBillingSheet
        }
        .sheet(item: $selectedInvoiceForPdf) { inv in
            gstInvoicePreviewSheet(invoice: inv)
        }
        .alert("Delete Order Project?", isPresented: $showDeleteConfirm) {
            Button("Cancel", role: .cancel) { }
            Button("Delete Permanently", role: .destructive) {
                if let order = selectedOrder {
                    viewModel.deleteOrder(orderId: order.id)
                }
            }
        } message: {
            Text("Are you sure you want to delete this order? All associated tasks, records, and files will be permanently removed.")
        }
    }
    
    // MARK: - Main Orders Directory & Board
    private var ordersDirectoryView: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header Console
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("OPERATIONS STUDIO • v1.1")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(.cyan)
                            .tracking(1.5)
                        Text("Orders")
                            .font(.system(size: 24, weight: .black))
                            .foregroundColor(.white)
                    }
                    Spacer()
                    
                    Picker("View Mode", selection: $viewMode) {
                        ForEach(OrderViewMode.allCases, id: \.self) { mode in
                            Text(mode.rawValue).tag(mode)
                        }
                    }
                    .pickerStyle(SegmentedPickerStyle())
                    .frame(width: 170)
                }
                
                Text("Manage assignments, task workbooks, customer requirements, billing, and project milestones.")
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
            
            // Search Bar & Filter Picker
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search orders, clients, email, PM...", text: $searchQuery)
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
                
                // Status Filter Chips
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        let filters = ["All", "Pending", "In Progress", "Pending Documents", "Documents Verified", "Completed"]
                        ForEach(filters, id: \.self) { f in
                            let isSel = viewModel.selectedOrderFilter == f
                            Button(action: { viewModel.selectedOrderFilter = f }) {
                                Text(f)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .foregroundColor(isSel ? .white : Color.textDark)
                                    .background(isSel ? Color.darkSlate : Color.white)
                                    .cornerRadius(14)
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(isSel ? Color.darkSlate : Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, 20)
            
            let filtered = viewModel.orders.filter { order in
                let q = searchQuery.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
                let matchesSearch = q.isEmpty ||
                    order.serviceName.lowercased().contains(q) ||
                    order.clientName.lowercased().contains(q) ||
                    order.email.lowercased().contains(q) ||
                    order.phone.lowercased().contains(q) ||
                    (order.assignedEmployee?.name ?? "").lowercased().contains(q)
                
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
                VStack(spacing: 12) {
                    if filtered.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "bag.badge.questionmark")
                                .font(.system(size: 36))
                                .foregroundColor(.textMuted)
                            Text("No orders found matching filter")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 40)
                    } else {
                        ForEach(filtered) { order in
                            orderListCard(order: order)
                        }
                    }
                }
                .padding(.horizontal, 20)
            } else {
                ordersKanbanBoard(orders: filtered)
            }
        }
    }
    
    // MARK: - Order List Card
    private func orderListCard(order: OrderResponse) -> some View {
        Button(action: { openOrderWorkspace(order: order) }) {
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
                    }
                    
                    Spacer()
                    
                    HStack(spacing: 6) {
                        Image(systemName: "person.crop.circle")
                            .font(.system(size: 12))
                            .foregroundColor(.indigo)
                        Text(order.assignedEmployee?.name ?? "Unassigned PM")
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
    
    // MARK: - Kanban Board
    private func ordersKanbanBoard(orders: [OrderResponse]) -> some View {
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
                                        .shadow(color: Color.black.opacity(0.03), radius: 4, y: 2)
                                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                        }
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
    
    // MARK: - 1:1 ORDER WORKSPACE SCREEN (Matches Web OrdersModule.jsx)
    private func orderWorkspaceView(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            // TOP CARD: Order Header, Inline Name Edit, Client Info, Actions & Assignment Grid
            VStack(alignment: .leading, spacing: 14) {
                // Top Header Row with Title & Quick Buttons
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        if isEditingName {
                            HStack(spacing: 8) {
                                TextField("Order Service Name", text: $editNameValue)
                                    .font(.system(size: 16, weight: .bold))
                                    .padding(8)
                                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .cornerRadius(8)
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.indigo, lineWidth: 2))
                                
                                Button(action: handleSaveOrderName) {
                                    if isSavingName {
                                        ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                                            .frame(width: 32, height: 32)
                                    } else {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(.white)
                                            .font(.system(size: 13, weight: .black))
                                            .frame(width: 32, height: 32)
                                    }
                                }
                                .background(Color.green)
                                .cornerRadius(8)
                                .disabled(isSavingName || editNameValue.isEmpty)
                                
                                Button(action: {
                                    isEditingName = false
                                    editNameValue = order.serviceName
                                }) {
                                    Image(systemName: "xmark")
                                        .foregroundColor(.textDark)
                                        .font(.system(size: 13, weight: .black))
                                        .frame(width: 32, height: 32)
                                        .background(Color.borderLight)
                                        .cornerRadius(8)
                                }
                            }
                        } else {
                            HStack(spacing: 8) {
                                Text(order.serviceName)
                                    .font(.system(size: 18, weight: .black))
                                    .foregroundColor(.textDark)
                                Button(action: {
                                    editNameValue = order.serviceName
                                    isEditingName = true
                                }) {
                                    Image(systemName: "pencil")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textMuted)
                                        .padding(4)
                                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                        .cornerRadius(6)
                                }
                            }
                        }
                        
                        HStack(spacing: 6) {
                            Text(order.clientName)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.indigo)
                            Text("• ₹\(Int(order.price))")
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        
                        HStack(spacing: 12) {
                            if !order.phone.isEmpty {
                                Button(action: {
                                    if let url = URL(string: "tel:\(order.phone.replacingOccurrences(of: " ", with: ""))") {
                                        UIApplication.shared.open(url)
                                    }
                                }) {
                                    HStack(spacing: 3) {
                                        Image(systemName: "phone.fill")
                                        Text("Call: \(order.phone)")
                                    }
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.indigo)
                                }
                            }
                            if !order.email.isEmpty {
                                Button(action: {
                                    if let url = URL(string: "mailto:\(order.email)") {
                                        UIApplication.shared.open(url)
                                    }
                                }) {
                                    HStack(spacing: 3) {
                                        Image(systemName: "envelope.fill")
                                        Text("Email: \(order.email)")
                                    }
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.indigo)
                                }
                            }
                        }
                    }
                    
                    Spacer()
                    
                    Button(action: { viewModel.selectedOrderId = "" }) {
                        Text("Back to Orders")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(8)
                    }
                }
                
                // Action Buttons: Raise Workflow Ticket & Make Recurring
                HStack(spacing: 10) {
                    Button(action: { showWorkflowTicketModal = true }) {
                        HStack(spacing: 4) {
                            Image(systemName: "shield.righthalf.filled")
                            Text("Raise Workflow Ticket")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.red)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(10)
                    }
                    
                    Button(action: { showMakeRecurringModal = true }) {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                            Text("Make Recurring")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.indigo)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.indigo.opacity(0.1))
                        .cornerRadius(10)
                    }
                    
                    Spacer()
                }
                
                Divider().background(Color.borderLight)
                
                // 5-Column Assignment & Status Grid
                VStack(spacing: 10) {
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("STATUS")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            Picker("Status", selection: $draftStatus) {
                                ForEach(["Pending", "In Progress", "Pending Documents", "Documents Verified", "Completed"], id: \.self) { s in
                                    Text(s).tag(s)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                        }
                        
                        VStack(alignment: .leading, spacing: 3) {
                            Text("PROJECT MANAGER")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            Picker("PM", selection: $draftPMId) {
                                Text("Unassigned").tag("")
                                ForEach(viewModel.employees) { emp in
                                    Text(emp.name).tag(emp.id)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                        }
                    }
                    
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("MAKER")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            Picker("Maker", selection: $draftMakerId) {
                                Text("Unassigned").tag("")
                                ForEach(viewModel.employees) { emp in
                                    Text(emp.name).tag(emp.id)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                        }
                        
                        VStack(alignment: .leading, spacing: 3) {
                            Text("CHECKER")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            Picker("Checker", selection: $draftCheckerId) {
                                Text("Unassigned").tag("")
                                ForEach(viewModel.employees) { emp in
                                    Text(emp.name).tag(emp.id)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                        }
                        
                        VStack(alignment: .leading, spacing: 3) {
                            Text("PRICE (₹)")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            TextField("Price", text: $draftPrice)
                                .font(.system(size: 12, weight: .bold))
                                .keyboardType(.numberPad)
                                .padding(6)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(8)
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                        }
                    }
                }
                
                HStack(spacing: 10) {
                    Button(action: handleSaveAssignments) {
                        HStack(spacing: 6) {
                            if isSavingAssignments {
                                ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Image(systemName: "checkmark.circle.fill")
                                Text("Save Package Assignment")
                            }
                        }
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 9)
                        .background(Color.indigo)
                        .cornerRadius(10)
                    }
                    .disabled(isSavingAssignments)
                    
                    if !saveSuccessMessage.isEmpty {
                        Text(saveSuccessMessage)
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.green)
                    }
                    
                    Spacer()
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 3)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color.borderLight, lineWidth: 1))
            .padding(.horizontal, 20)
            
            // 9 INNER WORKSPACE TABS SWITCHER
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(OrderWorkspaceTab.allCases, id: \.self) { tab in
                        let isSelected = selectedTab == tab
                        Button(action: { selectedTab = tab }) {
                            Text(tab.rawValue)
                                .font(.system(size: 12, weight: .bold))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 8)
                                .foregroundColor(isSelected ? .white : Color.textDark)
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
            
            // TAB CONTENT BODY
            VStack {
                switch selectedTab {
                case .overview:
                    workspaceOverviewTab(order: order)
                case .chat:
                    OrderChatView(orderId: order.id, currentUserRole: "admin", currentUserId: "")
                case .tasks:
                    workspaceTasksTab(order: order)
                case .requirements:
                    workspaceRequirementsTab(order: order)
                case .workflowTickets:
                    workspaceWorkflowTicketsTab(order: order)
                case .invoices:
                    workspaceInvoicesTab(order: order)
                case .todo:
                    workspaceTodoTab(order: order)
                case .transactions:
                    workspaceTransactionsTab(order: order)
                case .activities:
                    workspaceActivitiesTab(order: order)
                case .docs:
                    workspaceDocsVaultTab(order: order)
                }
            }
            .padding(.horizontal, 20)
        }
        .onAppear {
            loadOrderWorkspaceData(order: order)
        }
    }
    
    // MARK: - Workspace Tab 1: Overview
    private func workspaceOverviewTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            // 4 Metrics Cards
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                metricCard(label: "Tasks", value: "\(order.tasks.count)", icon: "checkmark.square", color: .indigo)
                metricCard(label: "Requirements", value: "\(order.customerRequirements.count)", icon: "doc.text", color: .orange)
                metricCard(label: "Invoices Raised", value: "\(order.invoices.count)", icon: "indianrupeesign.circle", color: .green)
                metricCard(label: "Service Budget", value: "₹\(Int(order.price))", icon: "clock", color: .pink)
            }
            
            // Freelancer Assignment & Payout Card
            freelancerAssignmentPanel(order: order)
            
            // To-Dos Checklist Card
            orderTodosChecklistPanel(order: order)
            
            // Active Staff Sessions Card
            activeStaffSessionsPanel(order: order)
            
            // ITR Assessment & Raise Balance Invoice (if applicable)
            if let itr = itrAssessment {
                itrChecklistDetailsPanel(itr: itr, order: order)
            }
            
            // Project Milestones Timeline
            milestonesTimelinePanel
        }
    }
    
    // MARK: - Freelancer Panel
    private func freelancerAssignmentPanel(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "person.2.fill")
                    .foregroundColor(.indigo)
                Text("Freelancer Assignment & Payout")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
            }
            
            if let fl = order.assignedFreelancer {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("ASSIGNED SPECIALIST")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            Text(fl.name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            if let p = fl.phone { Text(p).font(.system(size: 10)).foregroundColor(.textMuted) }
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) {
                            Text("DEFINED PAYOUT")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.textMuted)
                            Text("₹\(Int(order.freelancerPayout ?? 0))")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.green)
                            Text("CLAIMED")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.green)
                        }
                    }
                    
                    HStack(spacing: 8) {
                        Button(action: {
                            Task {
                                _ = try? await NetworkManager.shared.approveFreelancerPayout(orderId: order.id)
                                viewModel.toastMessage = "Work effort verified and payout approved!"
                                viewModel.syncDashboardData(silent: true)
                            }
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "checkmark.seal.fill")
                                Text("Approve Work & Payout")
                            }
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(Color.darkSlate)
                            .cornerRadius(10)
                        }
                        
                        Button(action: {
                            Task {
                                _ = try? await NetworkManager.shared.assignFreelancerOrder(orderId: order.id, freelancerId: nil)
                                viewModel.toastMessage = "Freelancer assignment removed."
                                viewModel.syncDashboardData(silent: true)
                            }
                        }) {
                            Text("Remove")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.red)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 8)
                                .background(Color.red.opacity(0.1))
                                .cornerRadius(10)
                        }
                    }
                }
                .padding(12)
                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                .cornerRadius(12)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Option A: Broadcast to Pool")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(.textMuted)
                    HStack(spacing: 8) {
                        TextField("Define payout (₹)", text: $freelancerBroadcastPayout)
                            .font(.system(size: 12))
                            .keyboardType(.numberPad)
                            .padding(8)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                        
                        Button(action: {
                            guard let payout = Double(freelancerBroadcastPayout), payout > 0 else { return }
                            Task {
                                _ = try? await NetworkManager.shared.broadcastFreelancerOrder(orderId: order.id, payout: payout)
                                viewModel.toastMessage = "Order broadcasted to specialist pool."
                                viewModel.syncDashboardData(silent: true)
                            }
                        }) {
                            Text("Broadcast")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.darkSlate)
                                .cornerRadius(8)
                        }
                    }
                    
                    Divider().background(Color.borderLight)
                    
                    Text("Option B: Direct Assignment")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(.textMuted)
                    HStack(spacing: 8) {
                        Picker("Specialist", selection: $selectedFreelancerId) {
                            Text("Select Freelancer...").tag("")
                            ForEach(viewModel.freelancers) { f in
                                Text(f.name).tag(f.id)
                            }
                        }
                        .pickerStyle(MenuPickerStyle())
                        .padding(6)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                        
                        TextField("Payout", text: $directFreelancerPayout)
                            .font(.system(size: 12))
                            .keyboardType(.numberPad)
                            .frame(width: 70)
                            .padding(8)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                        
                        Button(action: {
                            guard !selectedFreelancerId.isEmpty, let payout = Double(directFreelancerPayout) else { return }
                            Task {
                                _ = try? await NetworkManager.shared.assignFreelancerOrder(orderId: order.id, freelancerId: selectedFreelancerId, payout: payout)
                                viewModel.toastMessage = "Freelancer assigned directly."
                                viewModel.syncDashboardData(silent: true)
                            }
                        }) {
                            Text("Assign")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.indigo)
                                .cornerRadius(8)
                        }
                    }
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - To-Dos Checklist Panel
    private func orderTodosChecklistPanel(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.indigo)
                Text("To-Dos Checklist")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
            }
            
            HStack(spacing: 8) {
                TextField("Add new order-specific task...", text: $newTodoTitle)
                    .font(.system(size: 12))
                    .padding(8)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(8)
                
                Button(action: {
                    guard !newTodoTitle.isEmpty else { return }
                    Task {
                        _ = try? await NetworkManager.shared.createOrderTodo(orderId: order.id, title: newTodoTitle)
                        newTodoTitle = ""
                        orderTodos = (try? await NetworkManager.shared.getOrderTodos(orderId: order.id)) ?? []
                    }
                }) {
                    Image(systemName: "plus")
                        .foregroundColor(.white)
                        .font(.system(size: 12, weight: .black))
                        .padding(8)
                        .background(Color.indigo)
                        .cornerRadius(8)
                }
            }
            
            if orderTodos.isEmpty {
                Text("No task listed. Add one above!")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                VStack(spacing: 6) {
                    ForEach(orderTodos) { todo in
                        Button(action: {
                            Task {
                                let next = todo.status == "Completed" ? "Pending" : "Completed"
                                _ = try? await NetworkManager.shared.toggleOrderTodo(todoId: todo.id, newStatus: next)
                                orderTodos = (try? await NetworkManager.shared.getOrderTodos(orderId: order.id)) ?? []
                            }
                        }) {
                            HStack(spacing: 10) {
                                Image(systemName: todo.status == "Completed" ? "checkmark.square.fill" : "square")
                                    .foregroundColor(todo.status == "Completed" ? .indigo : .textMuted)
                                Text(todo.title)
                                    .font(.system(size: 12, weight: .medium))
                                    .strikethrough(todo.status == "Completed")
                                    .foregroundColor(todo.status == "Completed" ? .textMuted : .textDark)
                                Spacer()
                            }
                            .padding(8)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                        }
                    }
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - Active Staff Sessions Panel
    private func activeStaffSessionsPanel(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "person.crop.circle.badge.clock")
                    .foregroundColor(.indigo)
                Text("Active Staff Sessions")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
            }
            
            let assigned = [order.assignedEmployee, order.assignedMaker, order.assignedChecker, order.assignedProjectManager].compactMap { $0 }
            if assigned.isEmpty {
                Text("No staff members currently assigned.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                VStack(spacing: 6) {
                    ForEach(assigned) { emp in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(emp.name)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(emp.email)
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            HStack(spacing: 4) {
                                Circle().fill(Color.green).frame(width: 6, height: 6)
                                Text("Clocked In")
                                    .font(.system(size: 9, weight: .bold))
                                    .foregroundColor(.green)
                            }
                            .padding(.horizontal, 6)
                            .padding(.vertical, 3)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    }
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - ITR Checklist & Balance Invoice Panel
    private func itrChecklistDetailsPanel(itr: ITAssessmentResponse, order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "doc.plaintext.fill")
                    .foregroundColor(.indigo)
                Text("Client ITR Checklist & Balance Fees")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Text("PAN: \(itr.pan.uppercased())")
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(.indigo)
            }
            
            // Checked Items
            if let resps = itr.responses {
                let checked = resps.filter { $0.value.lowercased() == "yes" }
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(checked) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(item.description)
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Text("YES")
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(.green)
                                    .padding(.horizontal, 4)
                                    .padding(.vertical, 1)
                                    .background(Color.green.opacity(0.1))
                                    .cornerRadius(4)
                            }
                            if let rem = item.remarks, !rem.isEmpty {
                                Text("Remarks: \(rem)")
                                    .font(.system(size: 9))
                                    .foregroundColor(.textMuted)
                            }
                        }
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    }
                }
            }
            
            Divider().background(Color.borderLight)
            
            // Raise Balance Invoice Form
            VStack(alignment: .leading, spacing: 8) {
                Text("Raise Balance/Remaining Fees Invoice")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textDark)
                
                HStack(spacing: 8) {
                    TextField("Amount (₹)", text: $balanceInvoiceAmount)
                        .font(.system(size: 12))
                        .keyboardType(.numberPad)
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                    
                    TextField("Due Date (YYYY-MM-DD)", text: $balanceInvoiceDueDate)
                        .font(.system(size: 12))
                        .padding(8)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                }
                
                TextField("Notes", text: $balanceInvoiceNotes)
                    .font(.system(size: 12))
                    .padding(8)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(8)
                
                Button(action: {
                    guard let amt = Double(balanceInvoiceAmount), amt > 0 else { return }
                    isRaisingBalanceInvoice = true
                    Task {
                        let payload: [String: Any] = [
                            "packageName": order.packageName,
                            "amount": amt,
                            "adjustConsultation": false,
                            "adjustPreviousAmount": false,
                            "dueDate": balanceInvoiceDueDate,
                            "notes": balanceInvoiceNotes
                        ]
                        _ = try? await NetworkManager.shared.raiseAdjustedInvoice(orderId: order.id, payload: payload)
                        viewModel.toastMessage = "Balance invoice generated and emailed to client!"
                        balanceInvoiceAmount = ""
                        viewModel.syncDashboardData(silent: true)
                        isRaisingBalanceInvoice = false
                    }
                }) {
                    HStack(spacing: 4) {
                        if isRaisingBalanceInvoice {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Image(systemName: "paperplane.fill")
                            Text("Generate & Email Balance Invoice")
                        }
                    }
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(Color.green)
                    .cornerRadius(8)
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - Milestones Timeline
    private var milestonesTimelinePanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "clock.arrow.circlepath")
                    .foregroundColor(.indigo)
                Text("Project Milestones")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
            }
            
            if orderMilestones.isEmpty {
                Text("No milestones recorded yet.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(orderMilestones) { log in
                        HStack(alignment: .top, spacing: 10) {
                            Circle().fill(Color.indigo).frame(width: 8, height: 8).padding(.top, 4)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(log.action ?? "Update")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.indigo)
                                Text(log.description ?? "")
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(.textDark)
                                if let d = log.createdAt {
                                    Text(d).font(.system(size: 9)).foregroundColor(.textMuted)
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }
    
    // MARK: - Workspace Tab 2: Tasks
    private func workspaceTasksTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Task Workbook")
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
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.indigo)
                    .cornerRadius(8)
                }
            }
            
            let tasks = order.tasks
            if tasks.isEmpty {
                Text("No tasks populated in this workbook.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                ForEach(tasks) { task in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(task.title)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Role: \(task.ownerRole) • Status: \(task.status)")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            Menu {
                                ForEach(["Pending", "In Progress", "Completed", "Blocked"], id: \.self) { st in
                                    Button(st) {
                                        viewModel.updateTaskStatus(orderId: order.id, taskId: task.id, status: st)
                                    }
                                }
                            } label: {
                                Text(task.status.uppercased())
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(statusColor(task.status))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(statusColor(task.status).opacity(0.12))
                                    .cornerRadius(6)
                            }
                        }
                        
                        if !task.subtasks.isEmpty {
                            VStack(spacing: 4) {
                                ForEach(task.subtasks) { sub in
                                    HStack {
                                        Image(systemName: sub.isCompleted ? "checkmark.circle.fill" : "circle")
                                            .foregroundColor(sub.isCompleted ? .green : .textMuted)
                                        Text(sub.title)
                                            .font(.system(size: 11))
                                            .foregroundColor(sub.isCompleted ? .textMuted : .textDark)
                                        Spacer()
                                    }
                                    .padding(4)
                                }
                            }
                            .padding(8)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Workspace Tab 3: Requirements
    private func workspaceRequirementsTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Customer Requirements")
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
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.primaryRed)
                    .cornerRadius(8)
                }
            }
            
            let reqs = order.customerRequirements
            if reqs.isEmpty {
                Text("No requirements defined yet.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                ForEach(reqs) { req in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(req.title)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(req.description)
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            Menu {
                                ForEach(["Pending", "Uploaded", "Verified", "Rejected"], id: \.self) { st in
                                    Button(st) {
                                        viewModel.updateRequirementStatus(orderId: order.id, requirementId: req.id, status: st)
                                    }
                                }
                            } label: {
                                Text(req.status.uppercased())
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(statusColor(req.status))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(statusColor(req.status).opacity(0.12))
                                    .cornerRadius(6)
                            }
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Workspace Tab 4: Workflow Tickets
    private func workspaceWorkflowTicketsTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Internal Workflow Tickets")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: { showWorkflowTicketModal = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Raise Ticket")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.red)
                    .cornerRadius(8)
                }
            }
            
            if workflowTickets.isEmpty {
                Text("No workflow tickets opened for this project.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                ForEach(workflowTickets) { ticket in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(ticket.title)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Spacer()
                            Text(ticket.priority?.uppercased() ?? "MEDIUM")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.red)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.red.opacity(0.1))
                                .cornerRadius(4)
                        }
                        if let d = ticket.description {
                            Text(d).font(.system(size: 10)).foregroundColor(.textMuted)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Workspace Tab 5: Invoices
    private func workspaceInvoicesTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Commercial Invoices & Adjustments")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: { showInvoiceAdjustModal = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Initiate Billing")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.green)
                    .cornerRadius(8)
                }
            }
            
            let invoices = order.invoices
            if invoices.isEmpty {
                Text("No invoices raised yet.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                ForEach(invoices) { inv in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(inv.invoiceNumber)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("₹\(Int(inv.amount)) • \(inv.status)")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        Button(action: { selectedInvoiceForPdf = inv }) {
                            Text("GST PDF")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(.textDark)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                .cornerRadius(6)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Workspace Tab 6: ToDo
    private func workspaceTodoTab(order: OrderResponse) -> some View {
        orderTodosChecklistPanel(order: order)
    }
    
    // MARK: - Workspace Tab 7: Transactions
    private func workspaceTransactionsTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Payment Transactions")
                .font(.system(size: 14, weight: .black))
                .foregroundColor(.textDark)
            
            if orderPayments.isEmpty {
                Text("No transactions recorded yet.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            } else {
                ForEach(orderPayments) { p in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.paymentId)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("\(p.method) • \(p.createdAt)")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        Text("₹\(Int(p.amount))")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.green)
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Workspace Tab 8: Activities
    private func workspaceActivitiesTab(order: OrderResponse) -> some View {
        milestonesTimelinePanel
    }
    
    // MARK: - Workspace Tab 9: Docs Vault
    private func workspaceDocsVaultTab(order: OrderResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Documents Vault")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: {
                    viewModel.toastMessage = "Triggering batch downloads..."
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.down.doc.fill")
                        Text("Download All")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.indigo)
                    .cornerRadius(8)
                }
            }
            
            if let cert = order.finalCertificateUrl, !cert.isEmpty {
                HStack {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Final Incorporation Certificate")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textDark)
                        Text("Deliverable Certificate").font(.system(size: 10)).foregroundColor(.textMuted)
                    }
                    Spacer()
                    if let url = URL(string: cert) {
                        Link(destination: url) {
                            Image(systemName: "eye.fill")
                                .foregroundColor(.indigo)
                        }
                    }
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
            }
        }
    }
    
    // MARK: - Sheets & Actions
    private var raiseWorkflowTicketSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Ticket Info")) {
                    TextField("Ticket Title", text: $newTicketTitle)
                    Picker("Category", selection: $newTicketCategory) {
                        ForEach(["Technical", "Service", "Support", "Billing", "Compliance"], id: \.self) { c in
                            Text(c).tag(c)
                        }
                    }
                    Picker("Priority", selection: $newTicketPriority) {
                        ForEach(["Low", "Medium", "High", "Urgent"], id: \.self) { p in
                            Text(p).tag(p)
                        }
                    }
                    TextField("Description", text: $newTicketDesc)
                }
            }
            .navigationTitle("Raise Workflow Ticket")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { Button("Cancel") { showWorkflowTicketModal = false } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Submit") {
                        guard let order = selectedOrder, !newTicketTitle.isEmpty else { return }
                        Task {
                            _ = try? await NetworkManager.shared.createWorkflowTicket(
                                orderId: order.id,
                                title: newTicketTitle,
                                description: newTicketDesc,
                                category: newTicketCategory,
                                priority: newTicketPriority,
                                assignedTo: nil
                            )
                            showWorkflowTicketModal = false
                            workflowTickets = (try? await NetworkManager.shared.getWorkflowTickets(orderId: order.id)) ?? []
                            viewModel.toastMessage = "Workflow ticket raised!"
                        }
                    }
                }
            }
        }
    }
    
    private var makeRecurringSheet: some View {
        NavigationView {
            VStack(spacing: 20) {
                Text("Configure Recurring Subscription")
                    .font(.system(size: 14, weight: .bold))
                Text("Automate monthly/annual billing and compliance renewals for this client.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                Spacer()
            }
            .padding(20)
            .navigationTitle("Make Recurring")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { showMakeRecurringModal = false }
                }
            }
        }
    }
    
    private var addTaskSheet: some View {
        NavigationView {
            Form {
                TextField("Task Title", text: $newTaskTitle)
                Picker("Role", selection: $newTaskRole) {
                    Text("Maker").tag("Maker")
                    Text("Checker").tag("Checker")
                    Text("Project Manager").tag("PM")
                }
            }
            .navigationTitle("Add Task")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { Button("Cancel") { showAddTaskModal = false } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Add") {
                        if let order = selectedOrder, !newTaskTitle.isEmpty {
                            viewModel.addOrderTask(orderId: order.id, title: newTaskTitle, taskCode: "TASK-\(Int.random(in: 100...999))", description: "", ownerRole: newTaskRole)
                            showAddTaskModal = false
                        }
                    }
                }
            }
        }
    }
    
    private var raiseRequirementSheet: some View {
        NavigationView {
            Form {
                TextField("Requirement Title", text: $newReqTitle)
                TextField("Description / Instructions", text: $newReqDesc)
                Toggle("Mandatory Document", isOn: $newReqRequired)
            }
            .navigationTitle("Raise Requirement")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { Button("Cancel") { showRaiseReqModal = false } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Raise") {
                        if let order = selectedOrder, !newReqTitle.isEmpty {
                            viewModel.raiseRequirement(orderId: order.id, title: newReqTitle, description: newReqDesc)
                            showRaiseReqModal = false
                        }
                    }
                }
            }
        }
    }
    
    private var initiateBillingSheet: some View {
        NavigationView {
            Form {
                TextField("Package Name", text: $invPackageName)
                TextField("Amount (₹)", text: $invAmount).keyboardType(.numberPad)
                TextField("Due Date (YYYY-MM-DD)", text: $invDueDate)
                TextField("Notes", text: $invNotes)
            }
            .navigationTitle("Initiate Billing")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { Button("Cancel") { showInvoiceAdjustModal = false } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Dispatch") {
                        if let order = selectedOrder, let amt = Double(invAmount) {
                            Task {
                                let payload: [String: Any] = [
                                    "packageName": invPackageName.isEmpty ? order.packageName : invPackageName,
                                    "amount": amt,
                                    "adjustConsultation": invAdjustConsultation,
                                    "adjustPreviousAmount": invAdjustPrevious,
                                    "dueDate": invDueDate,
                                    "notes": invNotes
                                ]
                                _ = try? await NetworkManager.shared.raiseAdjustedInvoice(orderId: order.id, payload: payload)
                                showInvoiceAdjustModal = false
                                viewModel.toastMessage = "Invoice dispatched to client and admin!"
                                viewModel.syncDashboardData(silent: true)
                            }
                        }
                    }
                }
            }
        }
    }
    
    private func gstInvoicePreviewSheet(invoice: OrderInvoice) -> some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Invoice #\(invoice.invoiceNumber)")
                    .font(.system(size: 16, weight: .black))
                Text("Total Amount: ₹\(Int(invoice.amount))")
                    .font(.system(size: 14, weight: .bold))
                Text("Status: \(invoice.status)")
                    .font(.system(size: 12))
                Spacer()
            }
            .padding(20)
            .navigationTitle("GST Invoice Preview")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Close") { selectedInvoiceForPdf = nil }
                }
            }
        }
    }
    
    private func openOrderWorkspace(order: OrderResponse) {
        viewModel.selectedOrderId = order.id
        draftStatus = order.status
        draftPMId = order.assignedProjectManager?.id ?? order.assignedEmployee?.id ?? ""
        draftMakerId = order.assignedMaker?.id ?? ""
        draftCheckerId = order.assignedChecker?.id ?? ""
        draftPrice = "\(Int(order.price))"
        loadOrderWorkspaceData(order: order)
    }
    
    private func loadOrderWorkspaceData(order: OrderResponse) {
        Task {
            orderPayments = (try? await NetworkManager.shared.getOrderPayments(orderId: order.id)) ?? []
            orderMilestones = (try? await NetworkManager.shared.getOrderMilestones(orderId: order.id)) ?? []
            orderTodos = (try? await NetworkManager.shared.getOrderTodos(orderId: order.id)) ?? []
            workflowTickets = (try? await NetworkManager.shared.getWorkflowTickets(orderId: order.id)) ?? []
        }
    }
    
    private func handleSaveOrderName() {
        guard let order = selectedOrder, !editNameValue.isEmpty else { return }
        isSavingName = true
        Task {
            do {
                _ = try await NetworkManager.shared.updateOrderServiceName(orderId: order.id, serviceName: editNameValue)
                isEditingName = false
                viewModel.toastMessage = "Order name updated successfully!"
                viewModel.syncDashboardData(silent: true)
            } catch {
                viewModel.toastMessage = "Failed to update name."
            }
            isSavingName = false
        }
    }
    
    private func handleSaveAssignments() {
        guard let order = selectedOrder else { return }
        isSavingAssignments = true
        saveSuccessMessage = ""
        Task {
            viewModel.updateOrderStatus(orderId: order.id, status: draftStatus)
            viewModel.updateOrderAssignments(
                orderId: order.id,
                employeeId: draftPMId.isEmpty ? nil : draftPMId,
                makerId: draftMakerId.isEmpty ? nil : draftMakerId,
                checkerId: draftCheckerId.isEmpty ? nil : draftCheckerId,
                projectManagerId: draftPMId.isEmpty ? nil : draftPMId
            )
            if let p = Double(draftPrice) {
                viewModel.updateOrderCommercials(orderId: order.id, packageName: order.packageName, price: p, serviceName: order.serviceName)
            }
            saveSuccessMessage = "Saved!"
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { saveSuccessMessage = "" }
            isSavingAssignments = false
        }
    }
    
    private func metricCard(label: String, value: String, icon: String, color: Color) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label.uppercased())
                    .font(.system(size: 8, weight: .black))
                    .foregroundColor(.textMuted)
                Text(value)
                    .font(.system(size: 16, weight: .black))
                    .foregroundColor(.textDark)
            }
            Spacer()
            Image(systemName: icon)
                .font(.system(size: 16, weight: .bold))
                .foregroundColor(color)
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
    }
    
    private func statusBadge(status: String) -> some View {
        Text(status.uppercased())
            .font(.system(size: 9, weight: .black))
            .foregroundColor(statusColor(status))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(statusColor(status).opacity(0.12))
            .cornerRadius(8)
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "completed": return .green
        case "in progress", "processing": return .blue
        case "pending documents": return .orange
        case "documents verified": return .teal
        default: return .gray
        }
    }
}
