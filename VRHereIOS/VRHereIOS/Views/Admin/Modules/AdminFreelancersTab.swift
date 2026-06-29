import SwiftUI

struct AdminFreelancersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("GIG ECONOMY & CONTRACTORS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Freelancer Hub")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Outsource execution tasks, manage external professionals, and audit work statuses.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 20/255, blue: 10/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Freelancer network list
                VStack(spacing: 12) {
                    if viewModel.freelancers.isEmpty {
                        Text("No external freelancers registered")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 30)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else {
                        ForEach(viewModel.freelancers) { free in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(free.name)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(free.email)
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    // Status tag
                                    Text("ACTIVE")
                                        .font(.system(size: 8, weight: .bold))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(.green)
                                        .background(Color.green.opacity(0.12))
                                        .cornerRadius(6)
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    Text("Specialization: \(free.role.capitalized)")
                                        .font(.system(size: 9))
                                        .foregroundColor(.textMuted)
                                    Spacer()
                                    
                                    HStack(spacing: 2) {
                                        Image(systemName: "star.fill")
                                            .font(.system(size: 9))
                                            .foregroundColor(.yellow)
                                        Text("5.0")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.textDark)
                                    }
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
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
