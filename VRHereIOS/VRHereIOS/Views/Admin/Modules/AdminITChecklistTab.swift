import SwiftUI

struct AdminITChecklistTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var searchQuery: String = ""
    @State private var selectedAssessment: ITAssessmentResponse? = nil
    @State private var selectedStatus: String = "Pending"
    @State private var statusNotes: String = ""
    @State private var isSubmitting: Bool = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if selectedAssessment == nil {
                    // Header Console
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("TAX AUDIT & CHECKLIST VERIFICATIONS • v1.1")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(.cyan)
                                    .tracking(1.5)
                                Text("ITR Checklist Hub")
                                    .font(.system(size: 24, weight: .black))
                                    .foregroundColor(.white)
                            }
                            Spacer()
                            Button(action: {
                                viewModel.syncDashboardData()
                            }) {
                                Image(systemName: "arrow.triangle.2.circlepath")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(10)
                                    .background(Color.white.opacity(0.15))
                                    .cornerRadius(10)
                            }
                        }
                        
                        Text("Review digital checklist replies (1 to 51), verify attachment proofs, and track filing audit approvals client-wise.")
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
                    
                    // Search Bar
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.textMuted)
                        TextField("Search by client name or PAN...", text: $searchQuery)
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
                    .padding(.horizontal, 20)
                    
                    // Assessments List
                    VStack(spacing: 12) {
                        let filtered = viewModel.assessments.filter {
                            searchQuery.isEmpty ||
                            $0.clientName.localizedCaseInsensitiveContains(searchQuery) ||
                            $0.pan.localizedCaseInsensitiveContains(searchQuery)
                        }
                        
                        if filtered.isEmpty {
                            VStack(spacing: 8) {
                                Image(systemName: "doc.text.magnifyingglass")
                                    .font(.system(size: 32))
                                    .foregroundColor(.textMuted)
                                Text("No ITR assessment submissions found")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textMuted)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(40)
                            .background(Color.white)
                            .cornerRadius(16)
                            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                        } else {
                            ForEach(filtered) { item in
                                Button(action: {
                                    selectedAssessment = item
                                    selectedStatus = item.status
                                    statusNotes = item.notes ?? ""
                                }) {
                                    VStack(alignment: .leading, spacing: 10) {
                                        HStack {
                                            Circle()
                                                .fill(Color.indigoCustom.opacity(0.12))
                                                .frame(width: 36, height: 36)
                                                .overlay(
                                                    Text(String(item.clientName.prefix(1)).uppercased())
                                                        .font(.system(size: 14, weight: .black))
                                                        .foregroundColor(.indigoCustom)
                                                )
                                            
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(item.clientName)
                                                    .font(.system(size: 13, weight: .bold))
                                                    .foregroundColor(.textDark)
                                                Text("PAN: \(item.pan)")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.textMuted)
                                            }
                                            
                                            Spacer()
                                            
                                            Text(item.status.uppercased())
                                                .font(.system(size: 8, weight: .black))
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .foregroundColor(statusTextColor(item.status))
                                                .background(statusTextColor(item.status).opacity(0.12))
                                                .cornerRadius(6)
                                        }
                                        
                                        Divider().background(Color.borderLight)
                                        
                                        HStack {
                                            Text("FY \(item.financialYear) • AY \(item.assessmentYear)")
                                                .font(.system(size: 11, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            HStack(spacing: 4) {
                                                Text("Inspect Checklist")
                                                Image(systemName: "chevron.right")
                                            }
                                            .font(.system(size: 11, weight: .black))
                                            .foregroundColor(.indigoCustom)
                                        }
                                    }
                                    .padding(14)
                                    .background(Color.white)
                                    .cornerRadius(16)
                                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    
                } else if let item = selectedAssessment {
                    // MARK: - Inspect Detail View
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedAssessment = nil }) {
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.backward")
                                Text("Back to All Submissions")
                            }
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.indigoCustom)
                        }
                        .padding(.top, 16)
                        
                        // Client Detail Header Card
                        VStack(alignment: .leading, spacing: 8) {
                            Text(item.clientName)
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.white)
                            HStack(spacing: 12) {
                                Text("PAN: \(item.pan)")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.cyan)
                                Text("FY \(item.financialYear) • AY \(item.assessmentYear)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.white.opacity(0.8))
                            }
                        }
                        .padding(18)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.darkSlate)
                        .cornerRadius(18)
                        
                        // Status & Remarks Update Manager
                        VStack(alignment: .leading, spacing: 12) {
                            Text("AUDIT DECISION & INTERNAL CA NOTES")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.textMuted)
                            
                            HStack(spacing: 8) {
                                ForEach(["Pending", "In Progress", "Approved", "Rejected"], id: \.self) { st in
                                    let isSel = selectedStatus.lowercased() == st.lowercased()
                                    Button(action: { selectedStatus = st }) {
                                        Text(st)
                                            .font(.system(size: 10, weight: .black))
                                            .padding(.horizontal, 10)
                                            .padding(.vertical, 6)
                                            .foregroundColor(isSel ? .white : .textDark)
                                            .background(isSel ? statusTextColor(st) : Color.bgInput)
                                            .cornerRadius(8)
                                    }
                                }
                            }
                            
                            TextField("Add CA notes, verification remarks, or filing notes...", text: $statusNotes)
                                .font(.system(size: 12))
                                .padding(10)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            
                            Button(action: {
                                isSubmitting = true
                                Task {
                                    do {
                                        _ = try await NetworkManager.shared.updateIncomeTaxAssessmentStatus(id: item.id, status: selectedStatus, notes: statusNotes)
                                        viewModel.toastMessage = "Assessment status updated successfully"
                                        viewModel.syncDashboardData()
                                        selectedAssessment = nil
                                    } catch {
                                        viewModel.toastMessage = "Failed: \(error.localizedDescription)"
                                    }
                                    isSubmitting = false
                                }
                            }) {
                                HStack {
                                    Spacer()
                                    if isSubmitting {
                                        ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white))
                                    } else {
                                        Text("COMMIT AUDIT DECISION")
                                            .font(.system(size: 12, weight: .black))
                                    }
                                    Spacer()
                                }
                                .frame(height: 40)
                                .foregroundColor(.white)
                                .background(Color.indigoCustom)
                                .cornerRadius(10)
                            }
                            .disabled(isSubmitting)
                        }
                        .padding(14)
                        .background(Color.white)
                        .cornerRadius(16)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                        
                        // Responses Checklist (1 to 51)
                        VStack(alignment: .leading, spacing: 10) {
                            Text("ITR CHECKLIST QUESTIONNAIRE RESPONSES")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.textMuted)
                            
                            if let responses = item.responses, !responses.isEmpty {
                                ForEach(responses) { resp in
                                    ITRResponseCardView(response: resp)
                                }
                            } else {
                                Text("No detailed question responses submitted for this assessment.")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                    .padding(.vertical, 20)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }
    
    private func statusTextColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "approved": return .green
        case "in progress": return .orange
        case "rejected": return .red
        default: return Color.indigoCustom
        }
    }
}

// MARK: - ITR Response Card Subview
struct ITRResponseCardView: View {
    let response: ITAssessmentResponseItem
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(response.section.uppercased())
                    .font(.system(size: 8, weight: .black))
                    .foregroundColor(.textMuted)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.bgInput)
                    .cornerRadius(4)
                
                Spacer()
                
                Text(response.value.uppercased())
                    .font(.system(size: 8, weight: .black))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .foregroundColor(valueColor(response.value))
                    .background(valueColor(response.value).opacity(0.12))
                    .cornerRadius(6)
            }
            
            Text(response.description)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.textDark)
            
            if let remarks = response.remarks, !remarks.isEmpty {
                Text("Client Remarks: \(remarks)")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(.textMuted)
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.bgLight)
                    .cornerRadius(6)
            }
            
            if let proofUrl = response.documentUrl, let url = URL(string: proofUrl) {
                Link(destination: url) {
                    HStack(spacing: 4) {
                        Image(systemName: "doc.text.fill")
                        Text("View Uploaded Proof")
                        Image(systemName: "arrow.up.right")
                    }
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(.indigoCustom)
                    .padding(.top, 2)
                }
            }
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(response.value.lowercased() == "yes" ? Color.indigoCustom.opacity(0.3) : Color.borderLight, lineWidth: 1)
        )
    }
    
    private func valueColor(_ val: String) -> Color {
        switch val.lowercased() {
        case "yes": return .green
        case "no": return .red
        default: return .gray
        }
    }
}
