import SwiftUI

struct AdminComplianceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var activeCategory = "All"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Compliance Panel")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(["All", "GST", "MCA", "ESI", "TDS"], id: \.self) { cat in
                            Button(action: { activeCategory = cat }) {
                                Text(cat)
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(activeCategory == cat ? .white : .textMuted)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .background(activeCategory == cat ? Color.red : Color.white)
                                    .cornerRadius(20)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                VStack(spacing: 12) {
                    let items = [
                        ("GSTR-1 Return Filing", "GST", "2026-06-11", "Pending"),
                        ("SPICe+ Director DIN KYC", "MCA", "2026-05-31", "Filed"),
                        ("ESI Return Filing", "ESI", "2026-06-15", "Late"),
                        ("TDS Q4 Return", "TDS", "2026-05-24", "Missed")
                    ].filter { activeCategory == "All" || $0.1 == activeCategory }
                    
                    ForEach(items, id: \.0) { title, cat, date, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Category: \(cat) • Due: \(date)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Filed" ? Color.green : Color.red)
                                .cornerRadius(6)
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
