import SwiftUI

struct AdminKbTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("COMPLIANCE GUIDELINES & MANUALS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("KB Hub Desk")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Access statutory filing manuals, incorporation guides, and legal checklists.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 35/255, green: 35/255, blue: 10/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Knowledge Articles list
                VStack(alignment: .leading, spacing: 14) {
                    Text("KNOWLEDGE MANUALS")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    let manuals = [
                        ("Private Limited Company Audits", "Detailed checklist covering board resolutions, AOC-4, and MGT-7 filings.", "GST & Incorporation"),
                        ("GST Annual Return Filing Guide", "Step-by-step walkthrough for preparing and filing GSTR-9 and GSTR-9C forms.", "GST Filing"),
                        ("IEC Import Export Code Setup", "Compliance requirements and documentation for getting and maintaining an IEC certificate.", "Incorporation"),
                        ("LLP Agreement Amendment Flow", "Detailed instructions on shifting registered offices or updating partner agreements.", "Legal Audits")
                    ]
                    
                    VStack(spacing: 12) {
                        ForEach(manuals, id: \.0) { title, desc, tag in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(title)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    
                                    Text(tag.uppercased())
                                        .font(.system(size: 8, weight: .bold))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .foregroundColor(.blue)
                                        .background(Color.blue.opacity(0.12))
                                        .cornerRadius(4)
                                }
                                
                                Text(desc)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
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
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
