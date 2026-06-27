import SwiftUI

struct AdminTodoTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var newTaskTitle = ""
    @State private var selectedPriority = "Medium"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Tasks Board")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Add Todo field
                VStack(spacing: 8) {
                    TextField("Enter task title...", text: $newTaskTitle)
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(10)
                    
                    HStack {
                        Text("Priority:")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                        Picker("Priority", selection: $selectedPriority) {
                            Text("Low").tag("Low")
                            Text("Medium").tag("Medium")
                            Text("High").tag("High")
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        
                        Button("Add Task") {
                            guard !newTaskTitle.isEmpty else { return }
                            let req = CreateTodoRequest(title: newTaskTitle, description: "", priority: selectedPriority.lowercased(), orderId: nil)
                            viewModel.createTodo(request: req) { _ in
                                newTaskTitle = ""
                            }
                        }
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.red)
                    }
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                // List Tasks
                VStack(spacing: 12) {
                    ForEach(viewModel.todos) { todo in
                        HStack {
                            Image(systemName: todo.completed ? "checkmark.circle.fill" : "circle")
                                .foregroundColor(todo.completed ? .green : .gray)
                            
                            VStack(alignment: .leading, spacing: 4) {
                                Text(todo.title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                    .strikethrough(todo.completed)
                                Text("Priority: \(todo.priority.capitalized)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
