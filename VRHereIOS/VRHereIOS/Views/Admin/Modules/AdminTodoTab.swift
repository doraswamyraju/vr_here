import SwiftUI

struct AdminTodoTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var newTaskTitle = ""
    @State private var selectedPriority = "Medium"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("PLATFORM WORKFLOWS & WORKPACKS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Tasks Board")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Add dynamic system checklists, track active tasks, and complete operations items.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 45/255, green: 25/255, blue: 10/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Add Todo field
                VStack(alignment: .leading, spacing: 14) {
                    Text("CREATE SYSTEM CHECKLIST ITEM")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    TextField("Enter task title...", text: $newTaskTitle)
                        .padding(12)
                        .background(Color.bgInput)
                        .cornerRadius(10)
                    
                    HStack(spacing: 12) {
                        Picker("Priority", selection: $selectedPriority) {
                            Text("Low").tag("Low")
                            Text("Medium").tag("Medium")
                            Text("High").tag("High")
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        
                        Button("Add Task") {
                            guard !newTaskTitle.isEmpty else { return }
                            let req = CreateTodoRequest(title: newTaskTitle, description: "", priority: selectedPriority.lowercased(), assignedTo: nil, orderId: nil, dueDate: nil)
                            viewModel.createTodo(request: req) { _ in
                                newTaskTitle = ""
                            }
                        }
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(.white)
                        .padding(.horizontal, 14)
                        .frame(height: 32)
                        .background(Color.primaryRed)
                        .cornerRadius(8)
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
                .padding(16)
                .background(Color.white)
                .cornerRadius(18)
                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // List Tasks
                VStack(alignment: .leading, spacing: 12) {
                    Text("ACTIVE CHECKLISTS")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 10) {
                        if viewModel.todos.isEmpty {
                            Text("No checklist tasks found")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 20)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(viewModel.todos) { todo in
                                HStack(spacing: 14) {
                                    Button(action: {
                                        viewModel.toggleTodoStatus(todo: todo)
                                    }) {
                                        Image(systemName: todo.completed ? "checkmark.circle.fill" : "circle")
                                            .foregroundColor(todo.completed ? .green : .textMuted)
                                            .font(.system(size: 16))
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                    
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(todo.title)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(todo.completed ? .textMuted : .textDark)
                                            .strikethrough(todo.completed)
                                        Text("Priority: \(todo.priority.capitalized)")
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    // Small colored dot for priority
                                    Circle()
                                        .fill(priorityColor(todo.priority))
                                        .frame(width: 8, height: 8)
                                }
                                .padding(14)
                                .background(Color.white)
                                .cornerRadius(16)
                                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
    
    private func priorityColor(_ priority: String) -> Color {
        switch priority.lowercased() {
        case "high":
            return .red
        case "medium":
            return .orange
        default:
            return .gray
        }
    }
}
