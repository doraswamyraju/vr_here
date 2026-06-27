import SwiftUI

struct CustomerOrdersTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Binding var selectedOrderId: String
    let onSelectTab: (String) -> Void
    
    @Environment(\.openURL) private var openURL
    @State private var selectedCategory = "All"
    
    private let categories = ["All", "Active", "Completed", "Action Required"]
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if selectedOrderId.isEmpty {
                    Text("Your Compliance Orders")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    // Horizontal Categories Filter
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(categories, id: \.self) { category in
                                let isSelected = selectedCategory == category
                                Button(action: { selectedCategory = category }) {
                                    Text(category)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 8)
                                        .background(isSelected ? Color(red: 99/255, green: 102/255, blue: 241/255) : Color(red: 238/255, green: 242/255, blue: 246/255))
                                        .cornerRadius(12)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                    
                    let filteredOrders = viewModel.orders.filter { order in
                        switch selectedCategory {
                        case "Active":
                            return order.status != "Completed"
                        case "Completed":
                            return order.status == "Completed"
                        case "Action Required":
                            return order.status == "Pending Documents" || order.status == "Waiting for Clarification"
                        default:
                            return true
                        }
                    }
                    
                    if filteredOrders.isEmpty {
                        VStack(spacing: 16) {
                            Spacer().frame(height: 20)
                            VStack(spacing: 16) {
                                ZStack {
                                    Circle()
                                        .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                        .frame(width: 64, height: 64)
                                    Image(systemName: "folder.badge.questionmark")
                                        .font(.system(size: 28))
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                }
                                
                                VStack(spacing: 4) {
                                    Text("No Orders Found")
                                        .font(.system(size: 16, weight: .black))
                                        .foregroundColor(.textDark)
                                    Text("Looks like you haven't started any projects in this category.")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                        .multilineTextAlignment(.center)
                                }
                                .padding(.horizontal, 24)
                                
                                Button(action: { onSelectTab("Services") }) {
                                    Text("Browse Services")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 10)
                                        .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        .cornerRadius(12)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(.vertical, 32)
                            .frame(maxWidth: .infinity)
                            .background(Color.white)
                            .cornerRadius(24)
                            .overlay(
                                RoundedRectangle(cornerRadius: 24)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 8)
                            .padding(.horizontal, 20)
                        }
                    } else {
                        VStack(spacing: 12) {
                            ForEach(filteredOrders) { order in
                                Button(action: { selectedOrderId = order.id }) {
                                    VStack(alignment: .leading, spacing: 14) {
                                        HStack(spacing: 12) {
                                            Image(systemName: "briefcase.fill")
                                                .font(.system(size: 16))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                .frame(width: 44, height: 44)
                                                .background(Color.bgInput)
                                                .cornerRadius(12)
                                            
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(order.serviceName)
                                                    .font(.system(size: 13, weight: .bold))
                                                    .foregroundColor(.textDark)
                                                    .multilineTextAlignment(.leading)
                                                Text(order.packageName)
                                                    .font(.system(size: 11))
                                                    .foregroundColor(.textMuted)
                                            }
                                            
                                            Spacer()
                                            
                                            StatusBadgeWidgetView(status: order.status)
                                        }
                                        
                                        let completeness = getStatusProgressPercent(status: order.status)
                                        VStack(alignment: .leading, spacing: 6) {
                                            HStack {
                                                Text("COMPLETENESS")
                                                    .font(.system(size: 9, weight: .black))
                                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                                    .tracking(0.5)
                                                Spacer()
                                                Text("\(completeness)%")
                                                    .font(.system(size: 11, weight: .black))
                                                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                            }
                                            
                                            GeometryReader { geo in
                                                ZStack(alignment: .leading) {
                                                    RoundedRectangle(cornerRadius: 3)
                                                        .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                                        .frame(height: 6)
                                                    RoundedRectangle(cornerRadius: 3)
                                                        .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                        .frame(width: geo.size.width * CGFloat(Double(completeness) / 100.0), height: 6)
                                                }
                                            }
                                            .frame(height: 6)
                                        }
                                    }
                                    .padding(16)
                                    .glassCard()
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                } else if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                    // Order Drilldown View
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedOrderId = "" }) {
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.left")
                                    .font(.system(size: 14, weight: .bold))
                                Text("Back to Subscriptions")
                                    .font(.system(size: 13, weight: .bold))
                            }
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        }
                        .padding(.top, 16)
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        // 1. Project Header & Milestone Card
                        VStack(alignment: .leading, spacing: 16) {
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(order.serviceName)
                                        .font(.system(size: 18, weight: .black))
                                        .foregroundColor(.textDark)
                                        .multilineTextAlignment(.leading)
                                    Text(order.packageName)
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                StatusBadgeWidgetView(status: order.status)
                            }
                            
                            Divider().background(Color.borderLight)
                            
                            let completeness = getStatusProgressPercent(status: order.status)
                            VStack(alignment: .leading, spacing: 6) {
                                    HStack {
                                        Text("PROJECT COMPLETENESS")
                                            .font(.system(size: 10, weight: .black))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                        Spacer()
                                        Text("\(completeness)%")
                                            .font(.system(size: 12, weight: .black))
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    }
                                    
                                    GeometryReader { geo in
                                        ZStack(alignment: .leading) {
                                            RoundedRectangle(cornerRadius: 4)
                                                .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                                .frame(height: 8)
                                            RoundedRectangle(cornerRadius: 4)
                                                .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                .frame(width: geo.size.width * CGFloat(Double(completeness) / 100.0), height: 8)
                                        }
                                    }
                                    .frame(height: 8)
                            }
                            
                            Spacer().frame(height: 4)
                            
                            Text("Milestone Tracking Status")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.textDark)
                            
                            // Stepper vertical milestones
                            let milestones = ["Pending Documents", "Documents Verified", "Processing at Portal", "Waiting for Clarification", "Completed"]
                            let currentMilestoneIndex = milestones.firstIndex(of: order.status) ?? -1
                            
                            VStack(alignment: .leading, spacing: 12) {
                                ForEach(0..<milestones.count, id: \.self) { index in
                                    let milestone = milestones[index]
                                    let isCompleted = index < currentMilestoneIndex
                                    let isActive = index == currentMilestoneIndex
                                    
                                    HStack(spacing: 12) {
                                        ZStack {
                                            Circle()
                                                .fill(isActive ? Color(red: 99/255, green: 102/255, blue: 241/255) : (isCompleted ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color(red: 203/255, green: 213/255, blue: 225/255)))
                                                .frame(width: 18, height: 18)
                                            
                                            if isCompleted {
                                                Image(systemName: "checkmark")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.white)
                                            }
                                        }
                                        
                                        Text(milestone)
                                            .font(.system(size: 13, weight: isActive ? .black : .bold))
                                            .foregroundColor(isActive ? Color(red: 99/255, green: 102/255, blue: 241/255) : (isCompleted ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color.textMuted))
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 2. Latest Updates & Tasks Timeline
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Latest Updates & Tasks")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            
                            if order.tasks.isEmpty {
                                HStack(spacing: 8) {
                                    Image(systemName: "info.circle")
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    Text("No tasks or updates available yet.")
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.vertical, 8)
                            } else {
                                VStack(alignment: .leading, spacing: 16) {
                                    ForEach(order.tasks) { task in
                                        HStack(alignment: .top, spacing: 12) {
                                            let (iconName, iconColor) = { () -> (String, Color) in
                                                switch task.status {
                                                case "Completed":
                                                    return ("checkmark.circle.fill", Color(red: 16/255, green: 185/255, blue: 129/255))
                                                case "In Progress":
                                                    return ("clock.fill", Color(red: 99/255, green: 102/255, blue: 241/255))
                                                default:
                                                    return ("circle", Color(red: 148/255, green: 163/255, blue: 184/255))
                                                }
                                            }()
                                            
                                            Image(systemName: iconName)
                                                .font(.system(size: 16))
                                                .foregroundColor(iconColor)
                                                .frame(width: 20, height: 20)
                                            
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(task.title)
                                                    .font(.system(size: 13, weight: .black))
                                                    .foregroundColor(task.status == "Completed" ? Color.textMuted : Color.textDark)
                                                if !task.description.isEmpty {
                                                    Text(task.description)
                                                        .font(.system(size: 11))
                                                        .foregroundColor(.textMuted)
                                                        .multilineTextAlignment(.leading)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 3. Vault Requirements
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Vault Requirements")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            
                            if order.customerRequirements.isEmpty {
                                Text("No custom requirements requested for this order.")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                            } else {
                                VStack(spacing: 12) {
                                    ForEach(order.customerRequirements) { req in
                                        HStack(alignment: .center, spacing: 12) {
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(req.title)
                                                    .font(.system(size: 12, weight: .black))
                                                    .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                                    .multilineTextAlignment(.leading)
                                                Text(req.description)
                                                    .font(.system(size: 10))
                                                    .foregroundColor(.textMuted)
                                                    .multilineTextAlignment(.leading)
                                            }
                                            Spacer()
                                            
                                            let isVerified = req.status == "Verified"
                                            Text(req.status)
                                                .font(.system(size: 9, weight: .black))
                                                .foregroundColor(isVerified ? Color(red: 6/255, green: 95/255, blue: 70/255) : Color(red: 146/255, green: 64/255, blue: 14/255))
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .background(isVerified ? Color(red: 209/255, green: 250/255, blue: 229/255) : Color(red: 254/255, green: 243/255, blue: 199/255))
                                                .cornerRadius(6)
                                        }
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 4. Documents Summary Card
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                Text("Documents Summary")
                                    .font(.system(size: 15, weight: .black))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Button(action: { onSelectTab("Vault") }) {
                                    Text("Open Vault")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            
                            HStack(spacing: 12) {
                                // Client Uploads
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("MY UPLOADS")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.textMuted)
                                    Spacer().frame(height: 2)
                                    if order.clientDocuments.isEmpty {
                                        Text("No files uploaded")
                                            .font(.system(size: 11))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    } else {
                                        ForEach(Array(order.clientDocuments.prefix(3))) { doc in
                                            Button(action: {
                                                if let url = getAbsoluteURL(path: doc.url) {
                                                    openURL(url)
                                                }
                                            }) {
                                                HStack {
                                                    Text("• \(doc.name)")
                                                        .font(.system(size: 11))
                                                        .foregroundColor(.blue)
                                                        .lineLimit(1)
                                                        .multilineTextAlignment(.leading)
                                                    Spacer()
                                                }
                                            }
                                            .buttonStyle(PlainButtonStyle())
                                        }
                                        if order.clientDocuments.count > 3 {
                                            Text("+\(order.clientDocuments.count - 3) more...")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(14)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(16)
                                
                                // Admin Docs
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("ADMIN DOCS")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(.textMuted)
                                    Spacer().frame(height: 2)
                                    if order.adminDocuments.isEmpty {
                                        Text("No certificates yet")
                                            .font(.system(size: 11))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    } else {
                                        ForEach(Array(order.adminDocuments.prefix(3))) { doc in
                                            Button(action: {
                                                if let url = getAbsoluteURL(path: doc.url) {
                                                    openURL(url)
                                                }
                                            }) {
                                                HStack {
                                                    Text("• \(doc.name)")
                                                        .font(.system(size: 11))
                                                        .foregroundColor(.blue)
                                                        .lineLimit(1)
                                                        .multilineTextAlignment(.leading)
                                                    Spacer()
                                                }
                                            }
                                            .buttonStyle(PlainButtonStyle())
                                        }
                                        if order.adminDocuments.count > 3 {
                                            Text("+\(order.adminDocuments.count - 3) more...")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(14)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(16)
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 5. Assigned Expert Card
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Assigned Expert")
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.textDark)
                            
                            if let expert = order.assignedEmployee {
                                HStack(spacing: 12) {
                                    ZStack {
                                        Circle()
                                            .fill(Color(red: 238/255, green: 242/255, blue: 246/255))
                                            .frame(width: 44, height: 44)
                                        Image(systemName: "person.fill")
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(expert.name.isEmpty ? "Compliance Expert" : expert.name)
                                            .font(.system(size: 14, weight: .black))
                                            .foregroundColor(.textDark)
                                        Text(expert.role.isEmpty ? "Assigned Expert" : expert.role.uppercased())
                                            .font(.system(size: 9, weight: .black))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    }
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                VStack(alignment: .leading, spacing: 10) {
                                    if !expert.email.isEmpty {
                                        Button(action: {
                                            if let url = URL(string: "mailto:\(expert.email)") {
                                                UIApplication.shared.open(url)
                                            }
                                        }) {
                                            HStack(spacing: 8) {
                                                Image(systemName: "envelope.fill")
                                                    .font(.system(size: 14))
                                                    .foregroundColor(.textMuted)
                                                Text(expert.email)
                                                    .font(.system(size: 12))
                                                    .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                            }
                                        }
                                        .buttonStyle(PlainButtonStyle())
                                    }
                                    
                                    Button(action: {
                                        if let url = URL(string: "tel:918008530606") {
                                            UIApplication.shared.open(url)
                                        }
                                    }) {
                                        HStack(spacing: 8) {
                                            Image(systemName: "phone.fill")
                                                .font(.system(size: 14))
                                                .foregroundColor(.textMuted)
                                            Text("+91 80085 30606")
                                                .font(.system(size: 12))
                                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                        }
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            } else {
                                HStack(spacing: 8) {
                                    Image(systemName: "person.fill")
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    Text("Expert assignment pending.")
                                        .font(.system(size: 12))
                                        .foregroundColor(.textMuted)
                                }
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.vertical, 8)
                            }
                        }
                        .padding(20)
                        .glassCard()
                        
                        // 6. Financial Summary Card
                        let orderPayments = viewModel.payments.filter {
                            $0.serviceName == order.serviceName && $0.packageName == order.packageName
                        }
                        let totalPaid = orderPayments.filter { $0.status == "Completed" }.reduce(0.0) { $0 + $1.amount }
                        let balance = max(0.0, order.price - totalPaid)
                        
                        VStack(alignment: .leading, spacing: 14) {
                            HStack(spacing: 8) {
                                Image(systemName: "receipt")
                                    .font(.system(size: 16, weight: .bold))
                                    .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                Text("Financial Summary")
                                    .font(.system(size: 15, weight: .black))
                                    .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                            }
                            
                            VStack(spacing: 8) {
                                HStack {
                                    Text("Total Price")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(Color(red: 6/255, green: 95/255, blue: 70/255))
                                    Spacer()
                                    Text("₹\(Int(order.price))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                }
                                
                                HStack {
                                    Text("Amount Paid")
                                        .font(.system(size: 13))
                                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                    Spacer()
                                    Text("₹\(Int(totalPaid))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                }
                                
                                Divider().background(Color(red: 167/255, green: 243/255, blue: 208/255))
                                
                                HStack {
                                    Text("Balance Due")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                    Spacer()
                                    Text("₹\(Int(balance))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                }
                            }
                            
                            if !orderPayments.isEmpty {
                                Spacer().frame(height: 4)
                                Text("RECENT INVOICES")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                    .tracking(0.5)
                                
                                VStack(spacing: 8) {
                                    ForEach(orderPayments) { p in
                                        HStack {
                                            let dateString = p.createdAt.count >= 10 ? String(p.createdAt.prefix(10)) : "Recent"
                                            Text(dateString)
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                            Spacer()
                                            Text("₹\(Int(p.amount)) (\(p.status))")
                                                .font(.system(size: 11, weight: .bold))
                                                .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                                        }
                                    }
                                }
                            }
                        }
                        .padding(20)
                        .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                        .cornerRadius(24)
                        .overlay(
                            RoundedRectangle(cornerRadius: 24)
                                .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                        )
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

struct StatusBadgeWidgetView: View {
    let status: String
    
    var body: some View {
        let (bg, text) = colorsForStatus(status)
        Text(status)
            .font(.system(size: 9, weight: .black))
            .foregroundColor(text)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(bg)
            .cornerRadius(12)
    }
    
    private func colorsForStatus(_ status: String) -> (Color, Color) {
        switch status {
        case "Processing at Portal":
            return (Color(red: 219/255, green: 234/255, blue: 254/255), Color(red: 30/255, green: 64/255, blue: 175/255))
        case "Waiting for Clarification":
            return (Color(red: 243/255, green: 232/255, blue: 255/255), Color(red: 107/255, green: 33/255, blue: 168/255))
        case "Completed":
            return (Color(red: 209/255, green: 250/255, blue: 229/255), Color(red: 6/255, green: 95/255, blue: 70/255))
        case "Pending Documents":
            return (Color(red: 254/255, green: 243/255, blue: 199/255), Color(red: 146/255, green: 64/255, blue: 14/255))
        case "Documents Verified":
            return (Color(red: 236/255, green: 253/255, blue: 245/255), Color(red: 4/255, green: 120/255, blue: 87/255))
        default:
            return (Color(red: 241/255, green: 245/255, blue: 249/255), Color(red: 71/255, green: 85/255, blue: 105/255))
        }
    }
}

func getStatusProgressPercent(status: String) -> Int {
    switch status {
    case "Pending Documents": return 20
    case "Documents Verified": return 40
    case "Processing at Portal": return 60
    case "Waiting for Clarification": return 70
    case "Completed": return 100
    default: return 0
    }
}
