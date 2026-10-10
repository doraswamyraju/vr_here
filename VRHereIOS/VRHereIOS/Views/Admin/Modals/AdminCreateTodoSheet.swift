import SwiftUI

struct AdminCreateTodoSheet: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    let onDismiss: () -> Void
    
    @State private var taskType: String = "standalone" // "standalone" or "order"
    @State private var title = ""
    @State private var description = ""
    @State private var priority = "Medium"
    @State private var assignedToId = ""
    @State private var selectedOrderId = ""
    @State private var includeDueDate = false
    @State private var dueDate = Date()
    
    @State private var orderSearchTerm = ""
    @State private var isSubmitting = false
    @State private var errorMessage: String? = nil
    
    private let priorities = ["Low", "Medium", "High", "Urgent"]
    
    private var filteredOrders: [OrderResponse] {
        guard !orderSearchTerm.trimmingCharacters(in: .whitespaces).isEmpty else { return [] }
        let query = orderSearchTerm.lowercased()
        return viewModel.orders.filter { order in
            order.serviceName.lowercased().contains(query) ||
            order.clientName.lowercased().contains(query) ||
            order.id.lowercased().contains(query)
        }
    }
    
    var body: some View {
        NavigationView {
            ZStack {
                Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea()
                
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        
                        // Header Banner
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Image(systemName: "checkmark.square.fill")
                                    .foregroundColor(.blue)
                                Text("TASK DELEGATION CENTER")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.blue)
                                    .tracking(1.2)
                            }
                            Text("Assign New Task")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(.textPrimary)
                            Text("Direct task assignment and deadline tracking for your team.")
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 10)
                        
                        if let err = errorMessage {
                            HStack(spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(.red)
                                Text(err)
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.red)
                            }
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.red.opacity(0.1))
                            .cornerRadius(12)
                            .padding(.horizontal, 20)
                        }
                        
                        // Task Type Segmented Switch
                        HStack(spacing: 0) {
                            Button(action: {
                                taskType = "standalone"
                                selectedOrderId = ""
                            }) {
                                Text("Standalone Task")
                                    .font(.system(size: 13, weight: taskType == "standalone" ? .bold : .medium))
                                    .foregroundColor(taskType == "standalone" ? .blue : .textMuted)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(taskType == "standalone" ? Color.white : Color.clear)
                                    .cornerRadius(10)
                                    .shadow(color: taskType == "standalone" ? Color.black.opacity(0.06) : Color.clear, radius: 4, y: 2)
                            }
                            
                            Button(action: {
                                taskType = "order"
                            }) {
                                Text("Link to Order")
                                    .font(.system(size: 13, weight: taskType == "order" ? .bold : .medium))
                                    .foregroundColor(taskType == "order" ? .blue : .textMuted)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(taskType == "order" ? Color.white : Color.clear)
                                    .cornerRadius(10)
                                    .shadow(color: taskType == "order" ? Color.black.opacity(0.06) : Color.clear, radius: 4, y: 2)
                            }
                        }
                        .padding(4)
                        .background(Color.slateLight)
                        .cornerRadius(14)
                        .padding(.horizontal, 20)
                        
                        // Order Link Selector (if linked)
                        if taskType == "order" {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("LINKED CLIENT ORDER *")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                
                                if let selectedOrder = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(selectedOrder.serviceName)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textPrimary)
                                            Text("\(selectedOrder.clientName) • \(selectedOrder.id.prefix(8))")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        Button(action: {
                                            selectedOrderId = ""
                                            orderSearchTerm = ""
                                        }) {
                                            Image(systemName: "xmark.circle.fill")
                                                .foregroundColor(.textMuted)
                                        }
                                    }
                                    .padding(12)
                                    .background(Color.blue.opacity(0.08))
                                    .cornerRadius(12)
                                } else {
                                    VStack(spacing: 6) {
                                        HStack {
                                            Image(systemName: "magnifyingglass")
                                                .foregroundColor(.textMuted)
                                            TextField("Search active order or client...", text: $orderSearchTerm)
                                                .font(.system(size: 13))
                                        }
                                        .padding(12)
                                        .background(Color.white)
                                        .cornerRadius(12)
                                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                                        
                                        if !filteredOrders.isEmpty {
                                            VStack(alignment: .leading, spacing: 0) {
                                                ForEach(filteredOrders.prefix(5)) { ord in
                                                    Button(action: {
                                                        selectedOrderId = ord.id
                                                        orderSearchTerm = ""
                                                    }) {
                                                        HStack {
                                                            VStack(alignment: .leading, spacing: 2) {
                                                                Text(ord.serviceName)
                                                                    .font(.system(size: 12, weight: .bold))
                                                                    .foregroundColor(.textPrimary)
                                                                Text(ord.clientName)
                                                                    .font(.system(size: 11))
                                                                    .foregroundColor(.textMuted)
                                                            }
                                                            Spacer()
                                                            Image(systemName: "link")
                                                                .foregroundColor(.blue)
                                                        }
                                                        .padding(10)
                                                    }
                                                    Divider()
                                                }
                                            }
                                            .background(Color.white)
                                            .cornerRadius(12)
                                            .shadow(color: Color.black.opacity(0.06), radius: 6, y: 3)
                                        }
                                    }
                                }
                            }
                            .padding(16)
                            .background(Color.white)
                            .cornerRadius(20)
                            .padding(.horizontal, 20)
                        }
                        
                        // Task Details Card
                        VStack(alignment: .leading, spacing: 14) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("TASK TITLE *")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                TextField("e.g. Verify DSC & Upload ROC Form 3", text: $title)
                                    .font(.system(size: 13))
                                    .padding(12)
                                    .background(Color.white)
                                    .cornerRadius(12)
                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                            }
                            
                            VStack(alignment: .leading, spacing: 4) {
                                Text("DESCRIPTION & INSTRUCTIONS")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                TextEditor(text: $description)
                                    .font(.system(size: 13))
                                    .frame(minHeight: 80)
                                    .padding(8)
                                    .background(Color.white)
                                    .cornerRadius(12)
                                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                            }
                            
                            // Priority Selector
                            VStack(alignment: .leading, spacing: 4) {
                                Text("PRIORITY LEVEL")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                
                                HStack(spacing: 8) {
                                    ForEach(priorities, id: \.self) { p in
                                        Button(action: { priority = p }) {
                                            Text(p)
                                                .font(.system(size: 12, weight: priority == p ? .bold : .medium))
                                                .foregroundColor(priority == p ? .white : .textPrimary)
                                                .frame(maxWidth: .infinity)
                                                .padding(.vertical, 8)
                                                .background(priority == p ? priorityColor(p) : Color.slateLight)
                                                .cornerRadius(10)
                                        }
                                    }
                                }
                            }
                            
                            // Assignee Selector
                            VStack(alignment: .leading, spacing: 4) {
                                Text("ASSIGN SPECIALIST / EMPLOYEE")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                
                                Picker("Assign To", selection: $assignedToId) {
                                    Text("Unassigned").tag("")
                                    ForEach(viewModel.employees) { emp in
                                        Text("\(emp.name) (\(emp.designation ?? emp.role))").tag(emp.id)
                                    }
                                }
                                .pickerStyle(MenuPickerStyle())
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.white)
                                .cornerRadius(12)
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                            }
                            
                            // Due Date Toggle
                            Toggle(isOn: $includeDueDate) {
                                HStack(spacing: 6) {
                                    Image(systemName: "calendar")
                                        .foregroundColor(.blue)
                                    Text("Set Due Date")
                                        .font(.system(size: 13, weight: .semibold))
                                        .foregroundColor(.textPrimary)
                                }
                            }
                            .padding(.top, 4)
                            
                            if includeDueDate {
                                DatePicker("Deadline", selection: $dueDate, displayedComponents: [.date])
                                    .font(.system(size: 13))
                                    .datePickerStyle(CompactDatePickerStyle())
                                    .padding(8)
                                    .background(Color.slateLight)
                                    .cornerRadius(12)
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(.horizontal, 20)
                        
                        // Submit Buttons
                        HStack(spacing: 12) {
                            Button(action: onDismiss) {
                                Text("Cancel")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.textMuted)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 14)
                                    .background(Color.slateLight)
                                    .cornerRadius(14)
                            }
                            
                            Button(action: handleCreateTodo) {
                                HStack(spacing: 6) {
                                    if isSubmitting {
                                        ProgressView()
                                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                    } else {
                                        Image(systemName: "bolt.fill")
                                        Text("Assign Task")
                                    }
                                }
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 14)
                                .background(Color.blue)
                                .cornerRadius(14)
                                .shadow(color: Color.blue.opacity(0.35), radius: 8, y: 4)
                            }
                            .disabled(isSubmitting)
                        }
                        .padding(.horizontal, 20)
                        .padding(.bottom, 30)
                    }
                }
            }
            .navigationTitle("New Task")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: onDismiss) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.textMuted)
                    }
                }
            }
        }
    }
    
    private func priorityColor(_ p: String) -> Color {
        switch p.lowercased() {
        case "urgent": return .red
        case "high": return .orange
        case "medium": return .blue
        default: return .slateDark
        }
    }
    
    private func handleCreateTodo() {
        let trimmedTitle = title.trimmingCharacters(in: .whitespaces)
        if trimmedTitle.isEmpty {
            errorMessage = "Task title is required."
            return
        }
        
        errorMessage = nil
        isSubmitting = true
        
        let formatter = ISO8601DateFormatter()
        let dueDateString = includeDueDate ? formatter.string(from: dueDate) : nil
        
        let request = CreateTodoRequest(
            title: trimmedTitle,
            description: description.isEmpty ? nil : description,
            priority: priority,
            assignedTo: assignedToId.isEmpty ? nil : assignedToId,
            orderId: (taskType == "order" && !selectedOrderId.isEmpty) ? selectedOrderId : nil,
            dueDate: dueDateString
        )
        
        viewModel.createTodo(request: request) { success in
            isSubmitting = false
            if success {
                onDismiss()
            }
        }
    }
}
