import SwiftUI

struct AdminITChecklistTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var selectedStatus = "Pending"
    @State private var activeNotes = ""
    @State private var editingAssessment: ITAssessmentResponse? = nil
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Income Tax Checklist Submissions")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                TextField("Search by client name or PAN...", text: $searchQuery)
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(10)
                    .padding(.horizontal, 20)
                
                VStack(spacing: 12) {
                    let filtered = viewModel.assessments.filter {
                        searchQuery.isEmpty ||
                        $0.clientName.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.pan.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    if filtered.isEmpty {
                        Text("No submissions matching query.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        ForEach(filtered) { item in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(item.clientName)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(item.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(item.status == "Approved" ? Color.green : (item.status == "Rejected" ? Color.red : Color.orange))
                                        .cornerRadius(6)
                                }
                                
                                HStack {
                                    Text("PAN: \(item.pan)")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    Text("FY \(item.financialYear) / AY \(item.assessmentYear)")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                
                                Button("Update Status") {
                                    editingAssessment = item
                                    selectedStatus = item.status
                                }
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.red)
                            }
                            .glassCardStyle()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .sheet(item: $editingAssessment) { item in
            VStack(alignment: .leading, spacing: 20) {
                Text("Update Assessment Status")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                
                Text(item.clientName)
                    .font(.system(size: 13, weight: .bold))
                
                Picker("Status", selection: $selectedStatus) {
                    Text("Pending").tag("Pending")
                    Text("In Progress").tag("In Progress")
                    Text("Approved").tag("Approved")
                    Text("Rejected").tag("Rejected")
                }
                .pickerStyle(SegmentedPickerStyle())
                
                TextField("Notes...", text: $activeNotes)
                    .padding(12)
                    .background(Color.bgLight)
                    .cornerRadius(10)
                
                HStack {
                    Button("Cancel") {
                        editingAssessment = nil
                    }
                    .foregroundColor(.gray)
                    
                    Spacer()
                    
                    Button("Save") {
                        viewModel.updateAssessmentStatus(id: item.id, status: selectedStatus, notes: activeNotes)
                        editingAssessment = nil
                    }
                    .foregroundColor(.red)
                }
                .font(.system(size: 14, weight: .bold))
            }
            .padding(24)
        }
    }
}
