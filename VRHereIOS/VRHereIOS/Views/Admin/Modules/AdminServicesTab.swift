import SwiftUI

struct AdminServicesTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Services Master Catalog")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let catalogs = [
                        ("Pvt Ltd Registration", "₹5,499"),
                        ("GST Registration", "₹2,569"),
                        ("Partnership Firm", "₹4,899"),
                        ("Income Tax Return", "₹1,499")
                    ]
                    
                    ForEach(catalogs, id: \.0) { name, price in
                        HStack {
                            Text(name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Spacer()
                            Text(price)
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.red)
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
