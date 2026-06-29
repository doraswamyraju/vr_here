import SwiftUI

struct AdminITChecklistTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedItem: ITAssessmentResponse? = nil
    @State private var notesText = ""
    @State private var selectedStatus = "Approved"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if selectedItem == nil {
                    // Header card
                    VStack(alignment: .leading, spacing: 8) {
                        Text("TAX AUDIT & REGULATORY ASSESSMENTS")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(.cyan)
                            .tracking(1)
                        Text("Income Tax Panel")
                            .font(.system(size: 24, weight: .black))
                            .foregroundColor(.white)
                        Text("Audit client PAN submissions, IT assessments, and filing verifications.")
                            .font(.system(size: 12))
                            .foregroundColor(.white.opacity(0.7))
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        LinearGradient(colors: [Color.darkSlate, Color(red: 45/255, green: 20/255, blue: 15/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .cornerRadius(20)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                    
                    // Assessment lists
                    VStack(spacing: 12) {
                        if viewModel.assessments.isEmpty {
                            Text("No tax assessments submitted")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(viewModel.assessments) { item in
                                Button(action: {
                                    selectedItem = item
                                    notesText = ""
                                    selectedStatus = item.status
                                }) {
                                    VStack(alignment: .leading, spacing: 10) {
                                        HStack {
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text(item.clientName)
                                                    .font(.system(size: 13, weight: .bold))
                                                    .foregroundColor(.textDark)
                                                Text("PAN: \(item.pan) • AY: \(item.assessmentYear)")
                                                    .font(.system(size: 10))
                                                    .foregroundColor(.textMuted)
                                            }
                                            Spacer()
                                            
                                            // Status pill
                                            Text(item.status.uppercased())
                                                .font(.system(size: 8, weight: .bold))
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .foregroundColor(statusColor(item.status))
                                                .background(statusColor(item.status).opacity(0.12))
                                                .cornerRadius(6)
                                        }
                                        
                                        Divider().background(Color.borderLight)
                                        
                                        HStack {
                                            Text("FY: \(item.financialYear)")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            Text("Review Details")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(.primaryRed)
                                        }
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
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    
                } else if let item = selectedItem {
                    // Review Sub-View details
                    VStack(alignment: .leading, spacing: 20) {
                        Button(action: { selectedItem = nil }) {
                            HStack(spacing: 6) {
                                Image(systemName: "chevron.backward")
                                Text("Back to Audits")
                            }
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.primaryRed)
                        }
                        .padding(.top, 16)
                        
                        Text("Audit: \(item.clientName)")
                            .font(.system(size: 22, weight: .black))
                            .foregroundColor(.textDark)
                        
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Filing Verification Details")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.textDark)
                            
                            detailRow(title: "PAN Number:", value: item.pan)
                            detailRow(title: "Financial Year:", value: item.financialYear)
                            detailRow(title: "Assessment Year:", value: item.assessmentYear)
                            detailRow(title: "Current Status:", value: item.status)
                            
                            Divider().background(Color.borderLight)
                            
                            Text("AUDIT UPDATE ACTIONS")
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.textMuted)
                            
                            // Selectable status segment
                            HStack(spacing: 8) {
                                ForEach(["Approved", "Rejected", "Pending"], id: \.self) { status in
                                    Button(action: { selectedStatus = status }) {
                                        Text(status.uppercased())
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(selectedStatus == status ? .white : .textDark)
                                            .frame(maxWidth: .infinity)
                                            .frame(height: 32)
                                            .background(selectedStatus == status ? statusColor(status) : Color.bgInput)
                                            .cornerRadius(6)
                                    }
                                }
                            }
                            
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Audit Notes:")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.textMuted)
                                
                                TextField("Add assessment details/notes...", text: $notesText)
                                    .padding(10)
                                    .background(Color.bgInput)
                                    .cornerRadius(8)
                            }
                            
                            // Commit updates
                            Button(action: {
                                viewModel.updateAssessmentStatus(id: item.id, status: selectedStatus, notes: notesText)
                                selectedItem = nil
                            }) {
                                Text("COMMIT AUDIT DECISION")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 44)
                                    .background(Color.primaryRed)
                                    .cornerRadius(10)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        .padding(18)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 4)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
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
        }
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "approved", "completed":
            return .green
        case "pending", "submitted":
            return .orange
        default:
            return .red
        }
    }
}
