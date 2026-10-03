import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

// MARK: - Standard KYC Document Model for 1:1 Vault Selection
struct StandardDocTypeModel: Identifiable {
    var id: String { title }
    let title: String
    let description: String
    let iconName: String
}

let STANDARD_KYC_DOCS_LIST: [StandardDocTypeModel] = [
    StandardDocTypeModel(title: "Aadhaar Card", description: "Identity & address proof of Director/Proprietor", iconName: "person.text.rectangle.fill"),
    StandardDocTypeModel(title: "PAN Card", description: "Permanent Account Number proof", iconName: "creditcard.fill"),
    StandardDocTypeModel(title: "GST Certificate", description: "Form GST REG-06 or GST registration application", iconName: "doc.plaintext.fill"),
    StandardDocTypeModel(title: "Cancelled Cheque", description: "Bank validation with IFSC & Acc No.", iconName: "building.columns.fill"),
    StandardDocTypeModel(title: "Business Address Proof", description: "Utility bill, electricity bill or registered rent agreement", iconName: "house.fill"),
    StandardDocTypeModel(title: "Incorporation Certificate", description: "MCA Certificate of Incorporation or Partnership Deed", iconName: "checkmark.seal.fill")
]

// MARK: - Main Customer Orders Tab (1:1 with Android CustomerOrdersTab.kt)
struct CustomerOrdersTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Binding var selectedOrderId: String
    let onSelectTab: (String) -> Void
    
    @Environment(\.openURL) private var openURL
    
    // Filter State
    @State private var selectedFilter = "all" // "all" | "active" | "action" | "completed"
    
    // Sub-tab inside Order Details: 'requirements' | 'documents' | 'financials'
    @State private var currentDetailTab = "requirements"
    
    // Requirement Sheet & Upload States
    @State private var activeReq: CustomerRequirement? = nil
    @State private var detailText = ""
    @State private var notesText = ""
    @State private var showRequirementSheet = false
    @State private var showVaultSelectionSheet = false
    @State private var isSubmittingReq = false
    @State private var reqFilter = "all" // "all" | "pending" | "completed"
    
    // Document Pickers
    @State private var showPhotoPicker = false
    @State private var selectedPhotoItem: PhotosPickerItem? = nil
    @State private var showDocPicker = false
    @State private var showCameraPicker = false
    @State private var cameraCapturedImage: UIImage? = nil
    
    // Support Ticket Query Sheet State
    @State private var showSupportModal = false
    @State private var querySubject = ""
    @State private var queryDescription = ""
    @State private var isSubmittingTicket = false
    
    // Razorpay / Payment Bottom Sheet State
    @State private var showPaymentBottomSheet = false
    
    var body: some View {
        Group {
            if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                // ==================== 1:1 ORDER DETAILS SCREEN ====================
                orderDetailsView(order: order)
            } else {
                // ==================== 1:1 ORDERS LIST SCREEN ====================
                ordersListView
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
        // Photo Picker for requirement document
        .photosPicker(isPresented: $showPhotoPicker, selection: $selectedPhotoItem, matching: .images)
        .onChange(of: selectedPhotoItem) { newItem in
            guard let item = newItem, let req = activeReq, !selectedOrderId.isEmpty else { return }
            isSubmittingReq = true
            Task {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    do {
                        let updatedOrder = try await NetworkManager.shared.uploadOrderRequirementDocument(
                            orderId: selectedOrderId,
                            requirementId: req.id,
                            fileData: data,
                            fileName: "\(req.title.replacingOccurrences(of: " ", with: "_")).jpg",
                            mimeType: "image/jpeg"
                        )
                        if let idx = viewModel.orders.firstIndex(where: { $0.id == updatedOrder.id }) {
                            viewModel.orders[idx] = updatedOrder
                        }
                        viewModel.toastMessage = "Document uploaded successfully!"
                        showRequirementSheet = false
                    } catch {
                        viewModel.toastMessage = "Upload failed: \(error.localizedDescription)"
                    }
                }
                isSubmittingReq = false
                selectedPhotoItem = nil
            }
        }
        // Document Picker for PDF/Files
        .fileImporter(isPresented: $showDocPicker, allowedContentTypes: [.pdf, .image, .data]) { result in
            guard let req = activeReq, !selectedOrderId.isEmpty else { return }
            switch result {
            case .success(let fileUrl):
                guard fileUrl.startAccessingSecurityScopedResource() else { return }
                defer { fileUrl.stopAccessingSecurityScopedResource() }
                if let data = try? Data(contentsOf: fileUrl) {
                    isSubmittingReq = true
                    Task {
                        do {
                            let fileName = fileUrl.lastPathComponent
                            let mimeType = fileUrl.pathExtension.lowercased() == "pdf" ? "application/pdf" : "image/jpeg"
                            let updatedOrder = try await NetworkManager.shared.uploadOrderRequirementDocument(
                                orderId: selectedOrderId,
                                requirementId: req.id,
                                fileData: data,
                                fileName: fileName,
                                mimeType: mimeType
                            )
                            if let idx = viewModel.orders.firstIndex(where: { $0.id == updatedOrder.id }) {
                                viewModel.orders[idx] = updatedOrder
                            }
                            viewModel.toastMessage = "Document uploaded successfully!"
                            showRequirementSheet = false
                        } catch {
                            viewModel.toastMessage = "Upload failed: \(error.localizedDescription)"
                        }
                        isSubmittingReq = false
                    }
                }
            case .failure(let error):
                viewModel.toastMessage = "File selection error: \(error.localizedDescription)"
            }
        }
        // Camera sheet
        .sheet(isPresented: $showCameraPicker) {
            CameraPickerView(selectedImage: $cameraCapturedImage)
        }
        .onChange(of: cameraCapturedImage) { img in
            guard let image = img, let req = activeReq, !selectedOrderId.isEmpty else { return }
            if let jpegData = image.jpegData(compressionQuality: 0.8) {
                isSubmittingReq = true
                Task {
                    do {
                        let updatedOrder = try await NetworkManager.shared.uploadOrderRequirementDocument(
                            orderId: selectedOrderId,
                            requirementId: req.id,
                            fileData: jpegData,
                            fileName: "camera_\(req.id).jpg",
                            mimeType: "image/jpeg"
                        )
                        if let idx = viewModel.orders.firstIndex(where: { $0.id == updatedOrder.id }) {
                            viewModel.orders[idx] = updatedOrder
                        }
                        viewModel.toastMessage = "Camera photo uploaded successfully!"
                        showRequirementSheet = false
                    } catch {
                        viewModel.toastMessage = "Upload failed: \(error.localizedDescription)"
                    }
                    isSubmittingReq = false
                    cameraCapturedImage = nil
                }
            }
        }
        // Requirement Fulfillment Sheet
        .sheet(isPresented: $showRequirementSheet) {
            requirementFulfillmentSheet
        }
        // Vault Standard Document Selection Sheet
        .sheet(isPresented: $showVaultSelectionSheet) {
            vaultStandardDocumentSelectionSheet
        }
        // Support Query Modal Sheet
        .sheet(isPresented: $showSupportModal) {
            supportQueryModalSheet
        }
    }
    
    // MARK: - ==================== ORDERS LIST SCREEN ====================
    private var ordersListView: some View {
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 14) {
                // Header Title & Filter Chips
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("My Service Orders")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text("Track, fulfill requirements & download filing certificates")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        Spacer()
                        Text("\(viewModel.orders.count)")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                            .clipShape(Capsule())
                    }
                    .padding(.top, 16)
                    
                    // Category Filter Pills
                    let activeCount = viewModel.orders.filter { $0.status != "Completed" }.count
                    let actionCount = viewModel.orders.filter { o in o.customerRequirements.contains(where: { !$0.isClientCompleted }) }.count
                    let completedCount = viewModel.orders.filter { $0.status == "Completed" }.count
                    
                    let filterOptions = [
                        ("all", "All Orders (\(viewModel.orders.count))"),
                        ("active", "Active (\(activeCount))"),
                        ("action", "Action Required (\(actionCount))"),
                        ("completed", "Completed (\(completedCount))")
                    ]
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(filterOptions, id: \.0) { key, label in
                                let isSelected = selectedFilter == key
                                Button(action: { selectedFilter = key }) {
                                    Text(label)
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                        .padding(.horizontal, 14)
                                        .padding(.vertical, 8)
                                        .background(isSelected ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color.white)
                                        .cornerRadius(12)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 12)
                                                .stroke(isSelected ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                        )
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                        }
                    }
                }
                
                // Filtered Orders List
                let filteredOrders = viewModel.orders.filter { order in
                    switch selectedFilter {
                    case "active":
                        return order.status != "Completed"
                    case "completed":
                        return order.status == "Completed"
                    case "action":
                        return order.customerRequirements.contains(where: { !$0.isClientCompleted })
                    default:
                        return true
                    }
                }
                
                if filteredOrders.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .font(.system(size: 44))
                            .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                            .padding(.top, 16)
                        
                        Text("No orders match selected filter")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        
                        Button(action: { onSelectTab("Services") }) {
                            Text("Browse Services Catalog")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 10)
                                .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .cornerRadius(12)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        .padding(.bottom, 16)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(24)
                    .background(Color.white)
                    .cornerRadius(20)
                    .overlay(
                        RoundedRectangle(cornerRadius: 20)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                } else {
                    VStack(spacing: 14) {
                        ForEach(filteredOrders) { order in
                            orderCardView(order: order)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
            .padding(.horizontal, 16)
        }
    }
    
    // MARK: - 1:1 ORDER CARD VIEW (MATCHING ANDROID)
    @ViewBuilder
    private func orderCardView(order: OrderResponse) -> some View {
        let pendingReqs = order.customerRequirements.filter { !$0.isClientCompleted }.count
        let progress = getStatusProgressPercent(status: order.status)
        
        let cardPayments = viewModel.payments.filter { p in
            p.orderId == order.id || p.order?.id == order.id || (p.serviceName.caseInsensitiveCompare(order.serviceName) == .orderedSame)
        }
        let cardPaid = cardPayments.filter { $0.status.caseInsensitiveCompare("Completed") == .orderedSame || $0.status.caseInsensitiveCompare("Paid") == .orderedSame }.reduce(0.0) { $0 + $1.amount }
        let unpaidInvoices = order.invoices.filter { $0.status.caseInsensitiveCompare("Sent") == .orderedSame || $0.status.caseInsensitiveCompare("Overdue") == .orderedSame }
        let cardBalance: Double = {
            if !unpaidInvoices.isEmpty {
                return unpaidInvoices.reduce(0.0) { $0 + $1.amount }
            } else if order.paymentStatus.caseInsensitiveCompare("Paid") == .orderedSame || !order.paymentId.isEmpty {
                return 0.0
            } else {
                return max(0.0, order.price - cardPaid)
            }
        }()
        
        Button(action: {
            selectedOrderId = order.id
            currentDetailTab = "requirements"
        }) {
            VStack(alignment: .leading, spacing: 12) {
                // Header: ID + Action Required Tag + Status Badges
                HStack(alignment: .center) {
                    HStack(spacing: 8) {
                        Text("#\(order.id.suffix(8).uppercased())")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(6)
                        
                        if pendingReqs > 0 {
                            Text("\(pendingReqs) Action Required")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                .cornerRadius(6)
                        }
                    }
                    
                    Spacer()
                    
                    HStack(spacing: 6) {
                        StatusBadgeWidgetView(status: order.status)
                        
                        if cardBalance <= 0.0 {
                            Text("PAID")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                                .cornerRadius(6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                                )
                        } else if cardPaid > 0.0 {
                            Text("₹\(Int(cardBalance)) DUE")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 180/255, green: 83/255, blue: 9/255))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 255/255, green: 251/255, blue: 235/255))
                                .cornerRadius(6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(red: 253/255, green: 230/255, blue: 138/255), lineWidth: 1)
                                )
                        } else {
                            Text("UNPAID")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                .cornerRadius(6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1)
                                )
                        }
                    }
                }
                
                // Service Title & Price
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(order.serviceName.isEmpty ? "Business Filing Order" : order.serviceName)
                            .font(.system(size: 15, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            .lineLimit(1)
                        Text("Package: \(order.packageName.isEmpty ? "Standard Professional" : order.packageName)")
                            .font(.system(size: 11))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    Spacer()
                    Text("₹\(Int(order.price))")
                        .font(.system(size: 16, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                }
                
                // Progress Bar
                VStack(spacing: 4) {
                    HStack {
                        Text("Filing Progress")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        Spacer()
                        Text("\(progress)%")
                            .font(.system(size: 10, weight: .black))
                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                    }
                    
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 3)
                                .fill(Color(red: 241/255, green: 245/255, blue: 249/255))
                                .frame(height: 6)
                            RoundedRectangle(cornerRadius: 3)
                                .fill(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .frame(width: geo.size.width * CGFloat(Double(progress) / 100.0), height: 6)
                        }
                    }
                    .frame(height: 6)
                }
                
                // Divider & Footer
                Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                
                HStack {
                    Text(order.updatedAt.count >= 10 ? "Updated: \(order.updatedAt.prefix(10))" : "Active Order")
                        .font(.system(size: 11))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Spacer()
                    Text("Manage Order ›")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    // MARK: - ==================== 1:1 ORDER DETAILS SCREEN ====================
    @ViewBuilder
    private func orderDetailsView(order: OrderResponse) -> some View {
        let requirements = order.customerRequirements
        let pendingRequirements = requirements.filter { !$0.isClientCompleted }
        let completedRequirements = requirements.filter { $0.isClientCompleted }
        let filteredRequirements = reqFilter == "pending" ? pendingRequirements : (reqFilter == "completed" ? completedRequirements : requirements)
        let reqProgressPercentage = requirements.isEmpty ? 100 : Int((Double(completedRequirements.count) / Double(requirements.count)) * 100.0)
        
        let orderPayments = viewModel.payments.filter { p in
            p.orderId == order.id || p.order?.id == order.id || (!order.paymentId.isEmpty && p.paymentId == order.paymentId)
        }
        let totalPaid = orderPayments.filter { $0.status.caseInsensitiveCompare("Completed") == .orderedSame || $0.status.caseInsensitiveCompare("Paid") == .orderedSame }.reduce(0.0) { $0 + $1.amount }
        let unpaidInvoices = order.invoices.filter { $0.status.caseInsensitiveCompare("Sent") == .orderedSame || $0.status.caseInsensitiveCompare("Overdue") == .orderedSame }
        let balance: Double = {
            if !unpaidInvoices.isEmpty {
                return unpaidInvoices.reduce(0.0) { $0 + $1.amount }
            } else if order.paymentStatus.caseInsensitiveCompare("Paid") == .orderedSame || (!order.paymentId.isEmpty && totalPaid >= order.price) {
                return 0.0
            } else {
                return max(0.0, order.price - totalPaid)
            }
        }()
        
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 14) {
                // --- TOP NAVIGATION HEADER ---
                VStack(spacing: 12) {
                    HStack(alignment: .center) {
                        Button(action: { selectedOrderId = "" }) {
                            Image(systemName: "arrow.left")
                                .font(.system(size: 16, weight: .bold))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                .frame(width: 40, height: 40)
                                .background(Color.white)
                                .cornerRadius(12)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(order.serviceName)
                                .font(.system(size: 17, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                .lineLimit(1)
                            Text("Order ID: #\(order.id.suffix(8).uppercased()) • \(order.packageName)")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        
                        Spacer()
                        
                        HStack(spacing: 6) {
                            StatusBadgeWidgetView(status: order.status)
                            if balance <= 0.0 {
                                Text("PAID IN FULL")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 4)
                                    .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                                    .cornerRadius(8)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 8)
                                            .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                                    )
                            } else if totalPaid > 0.0 {
                                Text("PARTIALLY PAID")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(Color(red: 180/255, green: 83/255, blue: 9/255))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 4)
                                    .background(Color(red: 255/255, green: 251/255, blue: 235/255))
                                    .cornerRadius(8)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 8)
                                            .stroke(Color(red: 253/255, green: 230/255, blue: 138/255), lineWidth: 1)
                                    )
                            } else {
                                Text("UNPAID")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 4)
                                    .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                    .cornerRadius(8)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 8)
                                            .stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1)
                                    )
                            }
                        }
                    }
                    .padding(.top, 16)
                    
                    // Quick Action Bar (Ask Support / Pay Balance)
                    HStack(spacing: 10) {
                        Button(action: {
                            querySubject = "Query regarding Order #\(order.id.suffix(8).uppercased()): \(order.serviceName)"
                            queryDescription = ""
                            showSupportModal = true
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "questionmark.circle.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                Text("Ask Support")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(Color(red: 30/255, green: 41/255, blue: 59/255))
                            }
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.white)
                            .cornerRadius(12)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1)
                            )
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                        
                        if balance > 0 {
                            Button(action: {
                                viewModel.initiateCheckout(
                                    serviceName: order.serviceName,
                                    packageName: order.packageName.isEmpty ? "Balance Payment" : order.packageName,
                                    amount: balance
                                )
                            }) {
                                HStack(spacing: 6) {
                                    Image(systemName: "creditcard.fill")
                                        .font(.system(size: 14))
                                    Text("Pay Balance ₹\(Int(balance))")
                                        .font(.system(size: 12, weight: .black))
                                }
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 44)
                                .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .cornerRadius(12)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                    }
                    
                    // Prominent Outstanding Balance Alert Banner
                    if balance > 0 {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color(red: 220/255, green: 38/255, blue: 38/255))
                                    .frame(width: 34, height: 34)
                                Image(systemName: "creditcard.fill")
                                    .font(.system(size: 15))
                                    .foregroundColor(.white)
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Pending Balance: ₹\(Int(balance))")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(Color(red: 153/255, green: 27/255, blue: 27/255))
                                Text("Total package ₹\(Int(order.price)) • Paid ₹\(Int(totalPaid))")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(Color(red: 190/255, green: 18/255, blue: 60/255))
                            }
                            
                            Spacer()
                            
                            Button(action: {
                                viewModel.initiateCheckout(
                                    serviceName: order.serviceName,
                                    packageName: order.packageName.isEmpty ? "Balance Settlement" : order.packageName,
                                    amount: balance
                                )
                            }) {
                                Text("Settle ₹\(Int(balance))")
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 8)
                                    .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                    .cornerRadius(10)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        .padding(12)
                        .background(Color(red: 255/255, green: 241/255, blue: 242/255))
                        .cornerRadius(16)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1)
                        )
                    }
                }
                
                // --- 5-PHASE TIMELINE STEPPER CARD (MATCHING WEB & ANDROID 100%) ---
                fivePhaseTimelineStepperCard(order: order)
                
                // --- DELIVERABLES READY ALERT BANNER ---
                if !order.adminDocuments.isEmpty || (order.finalCertificateUrl != nil && !order.finalCertificateUrl!.isEmpty) {
                    HStack(spacing: 10) {
                        Image(systemName: "checkmark.seal.fill")
                            .font(.system(size: 24))
                            .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Deliverables & Certificates Issued!")
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                            Text("Official documents are ready in your Vault")
                                .font(.system(size: 10))
                                .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                        }
                        
                        Spacer()
                        
                        Button(action: { currentDetailTab = "documents" }) {
                            Text("Go to Vault")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Color(red: 4/255, green: 120/255, blue: 87/255))
                                .cornerRadius(8)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    .padding(14)
                    .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                    .cornerRadius(16)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                    )
                }
                
                // --- 3 SUB-TABS (Requirements | Vault | Financials) ---
                HStack(spacing: 4) {
                    let subTabs = [
                        ("requirements", "Requirements", pendingRequirements.count),
                        ("documents", "Vault", order.adminDocuments.count + order.clientDocuments.count),
                        ("financials", "Financials", 0)
                    ]
                    
                    ForEach(subTabs, id: \.0) { key, title, badgeCount in
                        let isSelected = currentDetailTab == key
                        Button(action: { currentDetailTab = key }) {
                            HStack(spacing: 4) {
                                Text(title)
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(isSelected ? .white : Color(red: 100/255, green: 116/255, blue: 139/255))
                                
                                if badgeCount > 0 {
                                    Text("\(badgeCount)")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(isSelected ? .white : Color(red: 220/255, green: 38/255, blue: 38/255))
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(isSelected ? Color.white.opacity(0.25) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                        .clipShape(Capsule())
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(isSelected ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color.clear)
                            .cornerRadius(12)
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                }
                .padding(4)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
                
                // --- SUB-TAB CONTENTS ---
                switch currentDetailTab {
                case "requirements":
                    requirementsSubTabView(order: order, requirements: filteredRequirements, totalPaid: totalPaid, balance: balance, reqProgressPercentage: reqProgressPercentage, completedCount: completedRequirements.count, totalCount: requirements.count)
                case "documents":
                    vaultDeliverablesSubTabView(order: order)
                case "financials":
                    financialsSubTabView(order: order, orderPayments: orderPayments, totalPaid: totalPaid, balance: balance)
                default:
                    EmptyView()
                }
                
                Spacer().frame(height: 100)
            }
            .padding(.horizontal, 16)
        }
    }
    
    // MARK: - 5-PHASE TIMELINE STEPPER CARD
    @ViewBuilder
    private func fivePhaseTimelineStepperCard(order: OrderResponse) -> some View {
        let phases = [
            ("Pending Documents", "Docs"),
            ("Documents Verified", "Verified"),
            ("Processing at Portal", "Portal"),
            ("Waiting for Clarification", "Clarify"),
            ("Completed", "Done")
        ]
        
        let currentStep: Int = {
            switch order.status {
            case "Pending Documents": return 0
            case "Documents Verified": return 1
            case "Processing at Portal": return 2
            case "Waiting for Clarification": return 3
            case "Completed": return 4
            default: return 0
            }
        }()
        
        let progress = getStatusProgressPercent(status: order.status)
        
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Project Progress Overview")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Text("Live statutory lifecycle tracking")
                        .font(.system(size: 11))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                Spacer()
                Text("\(progress)% Complete")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1)
                    )
            }
            
            // Stepper Circles & Connectors
            HStack(spacing: 0) {
                ForEach(0..<phases.count, id: \.self) { idx in
                    let isDone = idx < currentStep || order.status == "Completed"
                    let isCurrent = idx == currentStep && order.status != "Completed"
                    
                    // Step Circle
                    ZStack {
                        Circle()
                            .fill(isDone ? Color(red: 16/255, green: 185/255, blue: 129/255) : (isCurrent ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color(red: 241/255, green: 245/255, blue: 249/255)))
                            .frame(width: 28, height: 28)
                            .overlay(
                                Circle()
                                    .stroke(isCurrent ? Color(red: 254/255, green: 205/255, blue: 211/255) : (isDone ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color(red: 226/255, green: 232/255, blue: 240/255)), lineWidth: isCurrent ? 2 : 1)
                            )
                        
                        if isDone {
                            Image(systemName: "checkmark")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.white)
                        } else {
                            Text("\(idx + 1)")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(isCurrent ? .white : Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                    }
                    
                    // Connecting Line
                    if idx < phases.count - 1 {
                        let isNextDone = idx < currentStep
                        Rectangle()
                            .fill(isNextDone ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                            .frame(height: 3)
                            .cornerRadius(1.5)
                    }
                }
            }
            .padding(.horizontal, 4)
            
            // Phase Labels
            HStack {
                ForEach(0..<phases.count, id: \.self) { idx in
                    let (_, shortLabel) = phases[idx]
                    let isDone = idx <= currentStep
                    let isCurrent = idx == currentStep
                    
                    Text(shortLabel)
                        .font(.system(size: 10, weight: isCurrent ? .black : (isDone ? .bold : .medium)))
                        .foregroundColor(isCurrent ? Color(red: 220/255, green: 38/255, blue: 38/255) : (isDone ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 148/255, green: 163/255, blue: 184/255)))
                        .frame(maxWidth: .infinity, alignment: .center)
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(20)
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
    }
    
    // MARK: - SUB-TAB 1: REQUIREMENTS & ACTION ITEMS VIEW
    @ViewBuilder
    private func requirementsSubTabView(
        order: OrderResponse,
        requirements: [CustomerRequirement],
        totalPaid: Double,
        balance: Double,
        reqProgressPercentage: Int,
        completedCount: Int,
        totalCount: Int
    ) -> some View {
        VStack(spacing: 14) {
            // Metrics Row (TOTAL FEE | PAID | BALANCE)
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("TOTAL FEE")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("₹\(Int(order.price))")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("PAID")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                    Text("₹\(Int(totalPaid))")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1))
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("BALANCE")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 190/255, green: 18/255, blue: 60/255))
                    Text("₹\(Int(balance))")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(Color(red: 153/255, green: 27/255, blue: 27/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1))
            }
            
            // Required Action Checklist Card
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Required Action Checklist")
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("\(reqProgressPercentage)% Completed (\(completedCount)/\(totalCount))")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    Spacer()
                    HStack(spacing: 4) {
                        let filterTabs = [("pending", "Pending"), ("completed", "Done"), ("all", "All")]
                        ForEach(filterTabs, id: \.0) { key, label in
                            let isSel = reqFilter == key
                            Button(action: { reqFilter = key }) {
                                Text(label)
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(isSel ? .white : Color(red: 100/255, green: 116/255, blue: 139/255))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(isSel ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                    .cornerRadius(8)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                }
                
                if requirements.isEmpty {
                    Text("No requirements in this category.")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .padding(.vertical, 8)
                } else {
                    VStack(spacing: 10) {
                        ForEach(requirements) { req in
                            let isVerified = req.status.caseInsensitiveCompare("Verified") == .orderedSame
                            let isSubmitted = req.status.caseInsensitiveCompare("Received") == .orderedSame || req.status.caseInsensitiveCompare("Submitted") == .orderedSame || req.isClientCompleted || !req.value.isEmpty
                            
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(alignment: .top) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(req.title)
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        if !req.description.isEmpty {
                                            Text(req.description)
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        }
                                    }
                                    Spacer()
                                    Text(isVerified ? "VERIFIED" : (isSubmitted ? "SUBMITTED" : "ACTION REQD"))
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(isVerified ? Color(red: 4/255, green: 120/255, blue: 87/255) : (isSubmitted ? Color(red: 29/255, green: 78/255, blue: 216/255) : Color(red: 190/255, green: 18/255, blue: 60/255)))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 3)
                                        .background(isVerified ? Color(red: 209/255, green: 250/255, blue: 229/255) : (isSubmitted ? Color(red: 219/255, green: 234/255, blue: 254/255) : Color(red: 255/255, green: 228/255, blue: 230/255)))
                                        .cornerRadius(6)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 6)
                                                .stroke(isVerified ? Color(red: 167/255, green: 243/255, blue: 208/255) : (isSubmitted ? Color(red: 191/255, green: 219/255, blue: 254/255) : Color(red: 254/255, green: 205/255, blue: 211/255)), lineWidth: 1)
                                        )
                                }
                                
                                if !req.value.isEmpty {
                                    HStack {
                                        Text("Submitted: \(req.value)")
                                            .font(.system(size: 11, weight: .semibold))
                                            .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                            .lineLimit(1)
                                        Spacer()
                                        if req.value.hasPrefix("http") || req.value.hasPrefix("/uploads") {
                                            Button(action: {
                                                if let url = getAbsoluteURL(path: req.value) {
                                                    openURL(url)
                                                }
                                            }) {
                                                Text("View Doc")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(Color(red: 37/255, green: 99/255, blue: 235/255))
                                            }
                                            .buttonStyle(PlainButtonStyle())
                                        }
                                    }
                                    .padding(8)
                                    .background(Color.white)
                                    .cornerRadius(8)
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                                }
                                
                                Button(action: {
                                    activeReq = req
                                    detailText = req.value
                                    notesText = req.clientNotes
                                    showRequirementSheet = true
                                }) {
                                    HStack(spacing: 6) {
                                        Image(systemName: "pencil")
                                            .font(.system(size: 12))
                                        Text(isSubmitted ? "Update Submission" : "Fulfill Requirement")
                                            .font(.system(size: 11, weight: .bold))
                                    }
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .background(isSubmitted ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color(red: 220/255, green: 38/255, blue: 38/255))
                                    .cornerRadius(10)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            }
                            .padding(14)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(14)
                            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                        }
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
            
            // Assigned Lead Expert / Compliance Advisor Card
            expertAdvisorCard(order: order)
        }
    }
    
    // MARK: - ASSIGNED EXPERT ADVISOR CARD
    @ViewBuilder
    private func expertAdvisorCard(order: OrderResponse) -> some View {
        let expert = order.assignedEmployee
        
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(expert != nil ? "Assigned Lead Expert" : "Compliance & Advisory Desk")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                Spacer()
                Text(expert != nil ? "VERIFIED" : "OFFICIAL DESK")
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(expert != nil ? Color(red: 67/255, green: 56/255, blue: 202/255) : Color(red: 220/255, green: 38/255, blue: 38/255))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(expert != nil ? Color(red: 238/255, green: 242/255, blue: 255/255) : Color(red: 254/255, green: 242/255, blue: 242/255))
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(expert != nil ? Color(red: 199/255, green: 210/255, blue: 254/255) : Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1)
                    )
            }
            
            if let exp = expert {
                HStack(spacing: 12) {
                    if let photo = exp.profilePhoto, !photo.isEmpty, let photoUrl = getAbsoluteURL(path: photo) {
                        AsyncImage(url: photoUrl) { phase in
                            if let image = phase.image {
                                image.resizable().scaledToFill()
                            } else {
                                Color(red: 79/255, green: 70/255, blue: 229/255)
                            }
                        }
                        .frame(width: 46, height: 46)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                    } else {
                        ZStack {
                            RoundedRectangle(cornerRadius: 14)
                                .fill(Color(red: 79/255, green: 70/255, blue: 229/255))
                                .frame(width: 46, height: 46)
                            Text(exp.name.isEmpty ? "E" : String(exp.name.prefix(1)).uppercased())
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(.white)
                        }
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text(exp.name.isEmpty ? "Compliance Lead" : exp.name)
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text(exp.role.isEmpty ? "LEAD OPERATIONS SPECIALIST" : exp.role.uppercased())
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                            .tracking(0.5)
                    }
                }
                
                Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                
                let expertEmail = exp.email.isEmpty ? "support@vrhere.in" : exp.email
                let expertPhone = (exp.phone ?? "").isEmpty ? "+91 80085 30606" : (exp.phone ?? "")
                
                VStack(spacing: 8) {
                    Button(action: {
                        if let url = URL(string: "mailto:\(expertEmail)") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .frame(width: 32, height: 32)
                                Image(systemName: "envelope.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Text(expertEmail)
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                .lineLimit(1)
                            Spacer()
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                    
                    Button(action: {
                        let cleanPhone = expertPhone.replacingOccurrences(of: " ", with: "")
                        if let url = URL(string: "tel:\(cleanPhone)") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .frame(width: 32, height: 32)
                                Image(systemName: "phone.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Text(expertPhone)
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                            Spacer()
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                
                Button(action: {
                    querySubject = "Query regarding Order #\(order.id.suffix(8).uppercased()): \(order.serviceName)"
                    queryDescription = ""
                    showSupportModal = true
                }) {
                    HStack(spacing: 8) {
                        Image(systemName: "bubble.left.and.bubble.right.fill")
                            .font(.system(size: 14))
                        Text("Message Expert")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(12)
                }
                .buttonStyle(ScaleOnPressButtonStyle())
            } else {
                HStack(spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 14)
                            .fill(Color(red: 220/255, green: 38/255, blue: 38/255))
                            .frame(width: 46, height: 46)
                        Text("VR")
                            .font(.system(size: 18, weight: .black))
                            .foregroundColor(.white)
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("VR HERE Advisory Desk")
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("CENTRAL OPERATIONS TEAM")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                            .tracking(0.5)
                    }
                }
                
                Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                
                VStack(spacing: 8) {
                    Button(action: {
                        if let url = URL(string: "mailto:support@vrhere.in") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .frame(width: 32, height: 32)
                                Image(systemName: "envelope.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Text("support@vrhere.in")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                            Spacer()
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                    
                    Button(action: {
                        if let url = URL(string: "tel:918008530606") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .frame(width: 32, height: 32)
                                Image(systemName: "phone.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Text("+91 80085 30606")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                            Spacer()
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                
                Button(action: {
                    querySubject = "Query regarding Order #\(order.id.suffix(8).uppercased()): \(order.serviceName)"
                    queryDescription = ""
                    showSupportModal = true
                }) {
                    HStack(spacing: 8) {
                        Image(systemName: "bubble.left.and.bubble.right.fill")
                            .font(.system(size: 14))
                        Text("Ask Query / Raise Ticket")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(12)
                }
                .buttonStyle(ScaleOnPressButtonStyle())
            }
        }
        .padding(18)
        .background(Color.white)
        .cornerRadius(20)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
        .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
    }
    
    // MARK: - SUB-TAB 2: VAULT & DELIVERABLES VIEW
    @ViewBuilder
    private func vaultDeliverablesSubTabView(order: OrderResponse) -> some View {
        VStack(spacing: 14) {
            // Government & Statutory Certificates
            VStack(alignment: .leading, spacing: 12) {
                Text("Government & Statutory Certificates")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                
                if order.adminDocuments.isEmpty && (order.finalCertificateUrl == nil || order.finalCertificateUrl!.isEmpty) {
                    Text("Official certificates will appear here once issued.")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                } else {
                    if let finalCert = order.finalCertificateUrl, !finalCert.isEmpty {
                        deliverableDocCard(name: "Final Certificate of Filing", url: finalCert, isCertificate: true)
                    }
                    ForEach(order.adminDocuments) { doc in
                        deliverableDocCard(name: doc.name, url: doc.url, isCertificate: true)
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
            
            // Order Uploads & Attachments
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Order Uploads & Attachments")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Spacer()
                    Button(action: { onSelectTab("Vault") }) {
                        Text("Open Full Vault ›")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                
                if order.clientDocuments.isEmpty {
                    Text("No files attached to this order.")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                } else {
                    ForEach(order.clientDocuments) { doc in
                        deliverableDocCard(name: doc.name, url: doc.url, isCertificate: false)
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
        }
    }
    
    @ViewBuilder
    private func deliverableDocCard(name: String, url: String, isCertificate: Bool) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(isCertificate ? Color(red: 6/255, green: 78/255, blue: 59/255) : Color(red: 15/255, green: 23/255, blue: 42/255))
                    .lineLimit(1)
                Text(isCertificate ? "Issued Certificate" : "Client Attachment")
                    .font(.system(size: 10))
                    .foregroundColor(isCertificate ? Color(red: 4/255, green: 120/255, blue: 87/255) : Color(red: 100/255, green: 116/255, blue: 139/255))
            }
            
            Spacer()
            
            Button(action: {
                if let fileUrl = getAbsoluteURL(path: url) {
                    openURL(fileUrl)
                }
            }) {
                Text(isCertificate ? "View Document" : "View File")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(isCertificate ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(isCertificate ? Color(red: 4/255, green: 120/255, blue: 87/255) : Color.white)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(isCertificate ? Color.clear : Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1)
                    )
            }
            .buttonStyle(ScaleOnPressButtonStyle())
        }
        .padding(12)
        .background(isCertificate ? Color(red: 236/255, green: 253/255, blue: 245/255) : Color(red: 248/255, green: 250/255, blue: 252/255))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(isCertificate ? Color(red: 167/255, green: 243/255, blue: 208/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
    }
    
    // MARK: - SUB-TAB 3: FINANCIALS & INVOICES VIEW
    @ViewBuilder
    private func financialsSubTabView(order: OrderResponse, orderPayments: [PaymentResponse], totalPaid: Double, balance: Double) -> some View {
        VStack(spacing: 14) {
            // Metrics Row
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("TOTAL FEE")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("₹\(Int(order.price))")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("PAID TO DATE")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                    Text("₹\(Int(totalPaid))")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 6/255, green: 78/255, blue: 59/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1))
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("OUTSTANDING")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 190/255, green: 18/255, blue: 60/255))
                    Text("₹\(Int(balance))")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 153/255, green: 27/255, blue: 27/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1))
            }
            
            // Payment Transactions Log Card
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Payment Transactions Log")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Spacer()
                    if balance > 0 {
                        Button(action: {
                            viewModel.initiateCheckout(
                                serviceName: order.serviceName,
                                packageName: order.packageName.isEmpty ? "Balance Settle" : order.packageName,
                                amount: balance
                            )
                        }) {
                            Text("Settle Balance")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .cornerRadius(8)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
                
                if orderPayments.isEmpty {
                    Text("No recorded payments yet.")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                } else {
                    VStack(spacing: 8) {
                        ForEach(orderPayments) { p in
                            let isPaid = p.status.caseInsensitiveCompare("Completed") == .orderedSame || p.status.caseInsensitiveCompare("Paid") == .orderedSame
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("₹\(Int(p.amount))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    Text("\(p.createdAt.count >= 10 ? String(p.createdAt.prefix(10)) : "Recent") • \(p.method)")
                                        .font(.system(size: 10))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                }
                                Spacer()
                                Text(p.status.uppercased())
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(isPaid ? Color(red: 4/255, green: 120/255, blue: 87/255) : Color(red: 180/255, green: 83/255, blue: 9/255))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 3)
                                    .background(isPaid ? Color(red: 209/255, green: 250/255, blue: 229/255) : Color(red: 254/255, green: 243/255, blue: 199/255))
                                    .cornerRadius(6)
                            }
                            .padding(12)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                        }
                    }
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(20)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
        }
    }
    
    // MARK: - REQUIREMENT FULFILLMENT MODAL SHEET
    @ViewBuilder
    private var requirementFulfillmentSheet: some View {
        if let req = activeReq {
            NavigationView {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(req.title)
                                .font(.system(size: 18, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text(req.description.isEmpty ? "Please submit requested information or document below." : req.description)
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        
                        if isSubmittingReq {
                            HStack(spacing: 12) {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: Color(red: 220/255, green: 38/255, blue: 38/255)))
                                Text("Submitting details...")
                                    .font(.system(size: 13, weight: .bold))
                            }
                            .padding(.vertical, 12)
                        } else {
                            if req.type == "Detail" {
                                // Text Detail Input Form
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("Your Input / Value")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                    TextField("Enter details...", text: $detailText)
                                        .padding(12)
                                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                        .cornerRadius(12)
                                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                                }
                                
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("Notes for Expert / CA (Optional)")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                    TextField("Add any extra notes...", text: $notesText)
                                        .padding(12)
                                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                        .cornerRadius(12)
                                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                                }
                                
                                Button(action: {
                                    isSubmittingReq = true
                                    Task {
                                        do {
                                            let updatedOrder = try await NetworkManager.shared.updateOrderRequirement(
                                                orderId: selectedOrderId,
                                                requirementId: req.id,
                                                clientValue: detailText,
                                                clientNotes: notesText,
                                                isClientCompleted: true
                                            )
                                            if let idx = viewModel.orders.firstIndex(where: { $0.id == updatedOrder.id }) {
                                                viewModel.orders[idx] = updatedOrder
                                            }
                                            viewModel.toastMessage = "Requirement submitted successfully!"
                                            showRequirementSheet = false
                                        } catch {
                                            viewModel.toastMessage = "Submission failed: \(error.localizedDescription)"
                                        }
                                        isSubmittingReq = false
                                    }
                                }) {
                                    Text("Submit Details for Verification")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(.white)
                                        .frame(maxWidth: .infinity)
                                        .frame(height: 48)
                                        .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                        .cornerRadius(12)
                                }
                                .buttonStyle(ScaleOnPressButtonStyle())
                            } else {
                                // Document requirement: 3 UPLOAD OPTIONS (1:1 with Android)
                                Text("Choose document submission method:")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                
                                // Option 1: Standard Verification Vault
                                Button(action: {
                                    showRequirementSheet = false
                                    showVaultSelectionSheet = true
                                }) {
                                    HStack(spacing: 12) {
                                        ZStack {
                                            Circle()
                                                .fill(Color(red: 219/255, green: 234/255, blue: 254/255))
                                                .frame(width: 36, height: 36)
                                            Image(systemName: "checkmark.shield.fill")
                                                .font(.system(size: 16))
                                                .foregroundColor(Color(red: 29/255, green: 78/255, blue: 216/255))
                                        }
                                        
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("Option 1: Standard Verification Vault")
                                                .font(.system(size: 12, weight: .black))
                                                .foregroundColor(Color(red: 30/255, green: 64/255, blue: 175/255))
                                            Text("Select from Aadhaar, PAN, GST, Cheque, Address Proof")
                                                .font(.system(size: 10))
                                                .foregroundColor(Color(red: 37/255, green: 99/255, blue: 235/255))
                                        }
                                        
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(Color(red: 29/255, green: 78/255, blue: 216/255))
                                    }
                                    .padding(14)
                                    .background(Color(red: 239/255, green: 246/255, blue: 255/255))
                                    .cornerRadius(14)
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(red: 191/255, green: 219/255, blue: 254/255), lineWidth: 1))
                                }
                                .buttonStyle(PlainButtonStyle())
                                
                                // Option 2: Upload from Device Storage / Photo Library
                                Button(action: {
                                    showDocPicker = true
                                }) {
                                    HStack(spacing: 12) {
                                        ZStack {
                                            Circle()
                                                .fill(Color(red: 241/255, green: 245/255, blue: 249/255))
                                                .frame(width: 36, height: 36)
                                            Image(systemName: "folder.fill")
                                                .font(.system(size: 16))
                                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                        }
                                        
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("Option 2: Upload from Phone Memory / Files")
                                                .font(.system(size: 12, weight: .black))
                                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            Text("Select PDF, PNG, JPG file from device storage")
                                                .font(.system(size: 10))
                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        }
                                        
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.gray)
                                    }
                                    .padding(14)
                                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                    .cornerRadius(14)
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                                }
                                .buttonStyle(PlainButtonStyle())
                                
                                // Option 3: Click a Photo with Camera
                                Button(action: {
                                    showCameraPicker = true
                                }) {
                                    HStack(spacing: 12) {
                                        ZStack {
                                            Circle()
                                                .fill(Color(red: 255/255, green: 228/255, blue: 230/255))
                                                .frame(width: 36, height: 36)
                                            Image(systemName: "camera.fill")
                                                .font(.system(size: 16))
                                                .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                        }
                                        
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("Option 3: Click a Photo with Camera")
                                                .font(.system(size: 12, weight: .black))
                                                .foregroundColor(Color(red: 153/255, green: 27/255, blue: 27/255))
                                            Text("Take a fresh picture using phone camera")
                                                .font(.system(size: 10))
                                                .foregroundColor(Color(red: 190/255, green: 18/255, blue: 60/255))
                                        }
                                        
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                    }
                                    .padding(14)
                                    .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                    .cornerRadius(14)
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(red: 254/255, green: 205/255, blue: 211/255), lineWidth: 1))
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(20)
                }
                .navigationTitle("Fulfill Requirement")
                .navigationBarTitleDisplayMode(.inline)
                .navigationBarItems(trailing: Button("Close") { showRequirementSheet = false })
            }
        }
    }
    
    // MARK: - VAULT STANDARD DOCUMENT SELECTION SHEET
    @ViewBuilder
    private var vaultStandardDocumentSelectionSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Select Vault Standard Document")
                            .font(.system(size: 18, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("Attach an auto-verified standard document from your central vault:")
                            .font(.system(size: 12))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    
                    VStack(spacing: 10) {
                        ForEach(STANDARD_KYC_DOCS_LIST) { docType in
                            Button(action: {
                                guard let req = activeReq, !selectedOrderId.isEmpty else { return }
                                isSubmittingReq = true
                                Task {
                                    do {
                                        let updatedOrder = try await NetworkManager.shared.updateOrderRequirement(
                                            orderId: selectedOrderId,
                                            requirementId: req.id,
                                            clientValue: docType.title,
                                            clientNotes: "Attached from Central Vault Standard Documents",
                                            isClientCompleted: true
                                        )
                                        if let idx = viewModel.orders.firstIndex(where: { $0.id == updatedOrder.id }) {
                                            viewModel.orders[idx] = updatedOrder
                                        }
                                        viewModel.toastMessage = "\(docType.title) attached from Vault!"
                                        showVaultSelectionSheet = false
                                    } catch {
                                        viewModel.toastMessage = "Attachment failed: \(error.localizedDescription)"
                                    }
                                    isSubmittingReq = false
                                }
                            }) {
                                HStack(spacing: 12) {
                                    Image(systemName: docType.iconName)
                                        .font(.system(size: 18))
                                        .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                        .frame(width: 32)
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(docType.title)
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        Text(docType.description)
                                            .font(.system(size: 10))
                                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    }
                                    
                                    Spacer()
                                    Image(systemName: "checkmark.circle.fill")
                                        .font(.system(size: 16))
                                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                }
                                .padding(14)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(14)
                                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                    }
                }
                .padding(20)
            }
            .navigationTitle("Standard Vault")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarItems(trailing: Button("Cancel") { showVaultSelectionSheet = false })
        }
    }
    
    // MARK: - SUPPORT QUERY MODAL SHEET
    @ViewBuilder
    private var supportQueryModalSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Ask Support on Order #\(selectedOrderId.suffix(8).uppercased())")
                            .font(.system(size: 18, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("Tag a question directly for your assigned compliance expert.")
                            .font(.system(size: 12))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Query Subject")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                        TextField("Enter subject...", text: $querySubject)
                            .padding(12)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                    }
                    
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Detailed Description / Question")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                        TextEditor(text: $queryDescription)
                            .frame(height: 100)
                            .padding(8)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                    }
                    
                    Button(action: {
                        if querySubject.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || queryDescription.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            viewModel.toastMessage = "Please fill in all fields"
                            return
                        }
                        isSubmittingTicket = true
                        Task {
                            do {
                                _ = try await NetworkManager.shared.createTicket(
                                    category: "Service",
                                    subject: querySubject,
                                    description: queryDescription,
                                    priority: "Medium"
                                )
                                viewModel.toastMessage = "Support ticket submitted successfully!"
                                showSupportModal = false
                                querySubject = ""
                                queryDescription = ""
                                viewModel.refreshAllData(silent: true)
                            } catch {
                                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
                            }
                            isSubmittingTicket = false
                        }
                    }) {
                        if isSubmittingTicket {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .frame(maxWidth: .infinity)
                                .frame(height: 48)
                                .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .cornerRadius(12)
                        } else {
                            Text("Send Query to Support Team")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 48)
                                .background(Color(red: 220/255, green: 38/255, blue: 38/255))
                                .cornerRadius(12)
                        }
                    }
                    .disabled(isSubmittingTicket)
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(20)
            }
            .navigationTitle("Ask Support")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarItems(trailing: Button("Cancel") { showSupportModal = false })
        }
    }
}

// MARK: - Reusable Status Badge Widget (1:1 with Android StatusBadgeWidget)
struct StatusBadgeWidgetView: View {
    let status: String
    
    var body: some View {
        let (bg, fg, border) = colorsForStatus(status)
        Text(status)
            .font(.system(size: 9, weight: .black))
            .foregroundColor(fg)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(bg)
            .cornerRadius(6)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(border, lineWidth: 1)
            )
    }
    
    private func colorsForStatus(_ status: String) -> (Color, Color, Color) {
        switch status {
        case "Processing at Portal":
            return (Color(red: 219/255, green: 234/255, blue: 254/255), Color(red: 29/255, green: 78/255, blue: 216/255), Color(red: 191/255, green: 219/255, blue: 254/255))
        case "Waiting for Clarification":
            return (Color(red: 243/255, green: 232/255, blue: 255/255), Color(red: 107/255, green: 33/255, blue: 168/255), Color(red: 233/255, green: 213/255, blue: 255/255))
        case "Completed":
            return (Color(red: 209/255, green: 250/255, blue: 229/255), Color(red: 4/255, green: 120/255, blue: 87/255), Color(red: 167/255, green: 243/255, blue: 208/255))
        case "Pending Documents":
            return (Color(red: 254/255, green: 243/255, blue: 199/255), Color(red: 180/255, green: 83/255, blue: 9/255), Color(red: 253/255, green: 230/255, blue: 138/255))
        case "Documents Verified":
            return (Color(red: 236/255, green: 253/255, blue: 245/255), Color(red: 4/255, green: 120/255, blue: 87/255), Color(red: 167/255, green: 243/255, blue: 208/255))
        default:
            return (Color(red: 241/255, green: 245/255, blue: 249/255), Color(red: 71/255, green: 85/255, blue: 105/255), Color(red: 226/255, green: 232/255, blue: 240/255))
        }
    }
}

// MARK: - Stepper Progress Percentage Calculation (1:1 with Android getStatusProgress)
func getStatusProgressPercent(status: String) -> Int {
    switch status {
    case "Pending Documents": return 20
    case "Documents Verified": return 40
    case "Processing at Portal": return 60
    case "Waiting for Clarification": return 70
    case "Completed": return 100
    default: return 10
    }
}

// MARK: - Camera Picker View for Requirement Photo Capture
struct CameraPickerView: UIViewControllerRepresentable {
    @Binding var selectedImage: UIImage?
    @Environment(\.presentationMode) var presentationMode
    
    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        if UIImagePickerController.isSourceTypeAvailable(.camera) {
            picker.sourceType = .camera
        } else {
            picker.sourceType = .photoLibrary
        }
        picker.delegate = context.coordinator
        return picker
    }
    
    func updateUIViewController(_ uiViewController: UIImagePickerController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, UINavigationControllerDelegate, UIImagePickerControllerDelegate {
        let parent: CameraPickerView
        
        init(_ parent: CameraPickerView) {
            self.parent = parent
        }
        
        func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey : Any]) {
            if let image = info[.originalImage] as? UIImage {
                parent.selectedImage = image
            }
            parent.presentationMode.wrappedValue.dismiss()
        }
        
        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            parent.presentationMode.wrappedValue.dismiss()
        }
    }
}
