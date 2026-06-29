import SwiftUI

struct AdminServicesTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("CORPORATE SERVICE CATALOG SETUP")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Services Master")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Configure corporate services, statutory fees, and package definitions.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 20/255, green: 20/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Services catalog list
                VStack(alignment: .leading, spacing: 14) {
                    Text("SERVICE MODULES")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                    
                    let items = ServiceCatalog.shared.items.values.sorted { $0.title < $1.title }
                    
                    VStack(spacing: 12) {
                        ForEach(items, id: \.id) { service in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(spacing: 12) {
                                    Image(systemName: service.iconKey)
                                        .font(.system(size: 16))
                                        .foregroundColor(.primaryRed)
                                        .frame(width: 24)
                                    
                                    Text(service.title)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    
                                    Text("\(service.packages.count) Packs")
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.textMuted)
                                }
                                
                                Text(service.description)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                    .lineLimit(2)
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
