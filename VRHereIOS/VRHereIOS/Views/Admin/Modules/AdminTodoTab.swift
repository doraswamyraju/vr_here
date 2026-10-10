import SwiftUI

struct AdminTodoTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var viewMode: TodoViewMode = .list
    @State private var statusFilter = "All"
    @State private var priorityFilter = "All"
    @State private var searchQuery = ""
    
    // Modal states
    @State private var showCreateModal = false
    @State private var showEditModal = false
    @State private var editingTodo: TodoResponse? = nil
    
    // Form States
    @State private var draftTitle = ""
    @State private var draftDescription = ""
    @State private var draftPriority = "Medium"
    @State private var draftStatus = "Pending"
    @State private var draftAssignedTo = ""
    @State private var draftOrderId = ""
    @State private var draftDueDate = Date()
    @State private var includeDueDate = false

    enum TodoViewMode: String, CaseIterable {
        case list = "List View"
        case kanban = "Board (Kanban)"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Banner
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("TASK COMMAND CENTER")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("To-Do & Operational Tasks")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        Picker("View Mode", selection: $viewMode) {
                            ForEach(TodoViewMode.allCases, id: \.self) { mode in
                                Text(mode.rawValue).tag(mode)
                            }
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        .frame(width: 170)
                    }
                    
                    Text("Track operational items, assign duties to team specialists, and link tasks to client orders.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 45/255, green: 25/255, blue: 15/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Add Task Quick Action Button
                HStack {
                    Button(action: {
                        resetDraftForm()
                        showCreateModal = true
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "plus.circle.fill")
                            Text("Create New To-Do Task")
                        }
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color.primaryRed)
                        .cornerRadius(14)
                        .shadow(color: Color.primaryRed.opacity(0.25), radius: 6, y: 3)
                    }
                }
                .padding(.horizontal, 20)
                
                // Search & Filter Bars
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search tasks by title or assignee...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                .padding(.horizontal, 20)
                
                // Status Filter Chips
                let statuses = ["All", "Pending", "In Progress", "Completed"]
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(statuses, id: \.self) { st in
                            filterChip(title: st, current: statusFilter) { statusFilter = st }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Priority Filter Chips
                let priorities = ["All", "High", "Medium", "Low"]
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(priorities, id: \.self) { p in
                            filterChip(title: "Priority: \(p)", current: priorityFilter == p ? "Priority: \(p)" : "Priority: \(priorityFilter)") {
                                priorityFilter = p
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Filtered Todos
                let filtered = viewModel.todos.filter { todo in
                    let q = searchQuery.lowercased()
                    let matchesSearch = q.isEmpty ||
                        todo.title.lowercased().contains(q) ||
                        (todo.description ?? "").lowercased().contains(q) ||
                        (todo.assignedTo?.name ?? "").lowercased().contains(q)
                    
                    let matchesStatus: Bool
                    if statusFilter == "All" {
                        matchesStatus = true
                    } else if statusFilter == "Completed" {
                        matchesStatus = todo.completed
                    } else if statusFilter == "Pending" {
                        matchesStatus = !todo.completed && todo.status.lowercased() != "in progress"
                    } else {
                        matchesStatus = todo.status.localizedCaseInsensitiveContains(statusFilter)
                    }
                    
                    let matchesPriority = priorityFilter == "All" || todo.priority.localizedCaseInsensitiveContains(priorityFilter)
                    
                    return matchesSearch && matchesStatus && matchesPriority
                }
                
                if viewMode == .list {
                    // List View Layout
                    VStack(spacing: 12) {
                        if filtered.isEmpty {
                            VStack(spacing: 10) {
                                Image(systemName: "checkmark.circle.badge.questionmark")
                                    .font(.system(size: 36))
                                    .foregroundColor(.textMuted)
                                Text("No to-do tasks found")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textMuted)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 40)
                        } else {
                            ForEach(filtered) { todo in
                                todoCard(todo: todo)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                } else {
                    // Kanban Board View Layout
                    kanbanBoard(todos: filtered)
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(isPresented: $showCreateModal) {
            createTaskSheet
        }
        .sheet(isPresented: $showEditModal) {
            editTaskSheet
        }
    }

    // MARK: - Todo Card (List View)
    private func todoCard(todo: TodoResponse) -> some View {
        HStack(alignment: .top, spacing: 14) {
            // Checkbox
            Button(action: {
                viewModel.toggleTodoStatus(todo: todo)
            }) {
                Image(systemName: todo.completed ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 20))
                    .foregroundColor(todo.completed ? .green : .textMuted)
            }
            .padding(.top, 2)
            
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(todo.title)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(todo.completed ? .textMuted : .textDark)
                        .strikethrough(todo.completed)
                    Spacer()
                    
                    priorityBadge(priority: todo.priority)
                }
                
                if let desc = todo.description, !desc.isEmpty {
                    Text(desc)
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                
                HStack(spacing: 10) {
                    if let emp = todo.assignedTo {
                        HStack(spacing: 4) {
                            Image(systemName: "person.crop.circle")
                            Text(emp.name)
                        }
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.indigo)
                    }
                    
                    if let ord = todo.orderId {
                        HStack(spacing: 4) {
                            Image(systemName: "bag.fill")
                            Text(ord.serviceName)
                        }
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.blue)
                    }
                    
                    if let due = todo.dueDate, !due.isEmpty {
                        HStack(spacing: 4) {
                            Image(systemName: "calendar")
                            Text("Due: \(due)")
                        }
                        .font(.system(size: 10))
                        .foregroundColor(.textMuted)
                    }
                    
                    Spacer()
                    
                    // Edit & Delete Actions
                    Button(action: {
                        editingTodo = todo
                        draftTitle = todo.title
                        draftDescription = todo.description ?? ""
                        draftPriority = todo.priority.capitalized
                        draftStatus = todo.status
                        draftAssignedTo = todo.assignedTo?.idVal ?? ""
                        draftOrderId = todo.orderId?.idVal ?? ""
                        showEditModal = true
                    }) {
                        Image(systemName: "pencil")
                            .font(.system(size: 11))
                            .foregroundColor(.blue)
                    }
                    
                    Button(action: {
                        viewModel.deleteTodo(id: todo.idVal)
                    }) {
                        Image(systemName: "trash")
                            .font(.system(size: 11))
                            .foregroundColor(.red.opacity(0.8))
                    }
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }

    // MARK: - Kanban Board (Todos)
    private func kanbanBoard(todos: [TodoResponse]) -> some View {
        let columns = ["Pending", "In Progress", "Completed"]
        
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(alignment: .top, spacing: 16) {
                ForEach(columns, id: \.self) { col in
                    let colTodos = todos.filter { t in
                        if col == "Pending" {
                            return !t.completed && t.status.lowercased() != "in progress"
                        } else if col == "Completed" {
                            return t.completed
                        } else {
                            return t.status.lowercased() == "in progress"
                        }
                    }
                    
                    VStack(alignment: .leading, spacing: 12) {
                        // Header
                        HStack {
                            Text(col)
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(.textDark)
                            Spacer()
                            Text("\(colTodos.count)")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 2)
                                .background(statusColor(col))
                                .cornerRadius(10)
                        }
                        
                        // Cards
                        ScrollView(.vertical, showsIndicators: false) {
                            VStack(spacing: 10) {
                                ForEach(colTodos) { todo in
                                    VStack(alignment: .leading, spacing: 6) {
                                        HStack {
                                            Text(todo.title)
                                                .font(.system(size: 12, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            priorityBadge(priority: todo.priority)
                                        }
                                        
                                        if let emp = todo.assignedTo {
                                            Text("Assignee: \(emp.name)")
                                                .font(.system(size: 10))
                                                .foregroundColor(.indigo)
                                        }
                                        
                                        HStack {
                                            Spacer()
                                            Menu {
                                                ForEach(columns, id: \.self) { targetCol in
                                                    Button(targetCol) {
                                                        viewModel.updateTodo(
                                                            id: todo.idVal,
                                                            title: todo.title,
                                                            description: todo.description,
                                                            priority: todo.priority,
                                                            status: targetCol,
                                                            assignedTo: todo.assignedTo?.idVal,
                                                            dueDate: todo.dueDate
                                                        )
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
                                    .cornerRadius(12)
                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
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

    // MARK: - Modals / Sheets
    private var createTaskSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Task Details")) {
                    TextField("Title", text: $draftTitle)
                    TextField("Description", text: $draftDescription)
                    Picker("Priority", selection: $draftPriority) {
                        Text("Low").tag("Low")
                        Text("Medium").tag("Medium")
                        Text("High").tag("High")
                        Text("Urgent").tag("Urgent")
                    }
                }
                
                Section(header: Text("Assignment & Links")) {
                    Picker("Assign Employee", selection: $draftAssignedTo) {
                        Text("None").tag("")
                        ForEach(viewModel.employees) { emp in
                            Text(emp.name).tag(emp.idVal)
                        }
                    }
                    
                    Picker("Linked Order", selection: $draftOrderId) {
                        Text("None").tag("")
                        ForEach(viewModel.orders) { ord in
                            Text("\(ord.clientName) - \(ord.serviceName)").tag(ord.idVal)
                        }
                    }
                }
            }
            .navigationTitle("New To-Do Task")
            .navigationBarItems(
                leading: Button("Cancel") { showCreateModal = false },
                trailing: Button("Create") {
                    let req = CreateTodoRequest(
                        title: draftTitle,
                        description: draftDescription.isEmpty ? nil : draftDescription,
                        priority: draftPriority.lowercased(),
                        assignedTo: draftAssignedTo.isEmpty ? nil : draftAssignedTo,
                        orderId: draftOrderId.isEmpty ? nil : draftOrderId,
                        dueDate: nil
                    )
                    viewModel.createTodo(request: req) { _ in
                        showCreateModal = false
                    }
                }
                .font(.headline)
                .disabled(draftTitle.isEmpty)
            )
        }
    }

    private var editTaskSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Task Details")) {
                    TextField("Title", text: $draftTitle)
                    TextField("Description", text: $draftDescription)
                    Picker("Priority", selection: $draftPriority) {
                        Text("Low").tag("Low")
                        Text("Medium").tag("Medium")
                        Text("High").tag("High")
                        Text("Urgent").tag("Urgent")
                    }
                    Picker("Status", selection: $draftStatus) {
                        Text("Pending").tag("Pending")
                        Text("In Progress").tag("In Progress")
                        Text("Completed").tag("Completed")
                    }
                }
                
                Section(header: Text("Assignment")) {
                    Picker("Assign Employee", selection: $draftAssignedTo) {
                        Text("None").tag("")
                        ForEach(viewModel.employees) { emp in
                            Text(emp.name).tag(emp.idVal)
                        }
                    }
                }
            }
            .navigationTitle("Edit To-Do Task")
            .navigationBarItems(
                leading: Button("Cancel") { showEditModal = false },
                trailing: Button("Save") {
                    if let todo = editingTodo {
                        viewModel.updateTodo(
                            id: todo.idVal,
                            title: draftTitle,
                            description: draftDescription.isEmpty ? nil : draftDescription,
                            priority: draftPriority.lowercased(),
                            status: draftStatus,
                            assignedTo: draftAssignedTo.isEmpty ? nil : draftAssignedTo,
                            dueDate: todo.dueDate
                        ) { _ in
                            showEditModal = false
                        }
                    }
                }
                .font(.headline)
                .disabled(draftTitle.isEmpty)
            )
        }
    }

    private func resetDraftForm() {
        draftTitle = ""
        draftDescription = ""
        draftPriority = "Medium"
        draftStatus = "Pending"
        draftAssignedTo = ""
        draftOrderId = ""
    }

    private func filterChip(title: String, current: String, action: @escaping () -> Void) -> some View {
        let isSelected = title == current
        return Button(action: action) {
            Text(title)
                .font(.system(size: 11, weight: .bold))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                .background(isSelected ? Color.primaryRed : Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(isSelected ? Color.primaryRed : Color.borderLight, lineWidth: 1))
        }
    }

    private func priorityBadge(priority: String) -> some View {
        let p = priority.lowercased()
        let color: Color
        if p == "high" || p == "urgent" {
            color = .red
        } else if p == "medium" {
            color = .orange
        } else {
            color = .blue
        }
        
        return Text(priority.uppercased())
            .font(.system(size: 8, weight: .black))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundColor(color)
            .background(color.opacity(0.12))
            .cornerRadius(4)
    }

    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "completed":
            return .green
        case "in progress":
            return .blue
        default:
            return .orange
        }
    }
}
