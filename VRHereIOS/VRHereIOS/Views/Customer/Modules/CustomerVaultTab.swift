import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

struct MasterKYCSlot: Identifiable {
    let id: String
    let title: String
    let desc: String
    let iconName: String
    let keywords: [String]
}

struct CustomerVaultTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    var isEmbedded: Bool = false
    @Environment(\.openURL) private var openURL
    
    @State private var selectedSection = "Standard" // "Standard" | "Deliverables"
    @State private var vaultDocuments: [UserVaultDocument] = []
    @State private var isLoading = true
    
    // Upload state & pickers
    @State private var activeSlotForUpload: MasterKYCSlot? = nil
    @State private var showUploadOptions = false
    @State private var showPhotoPicker = false
    @State private var showDocPicker = false
    @State private var selectedPhotoItem: PhotosPickerItem? = nil
    @State private var isUploading = false
    
    private let kycSlots = [
        MasterKYCSlot(id: "PAN Card", title: "PAN Card (Director/Company)", desc: "Permanent Account Number proof", iconName: "creditcard.fill", keywords: ["pan"]),
        MasterKYCSlot(id: "Aadhaar Card", title: "Aadhaar Card (Director)", desc: "Identity & address verification", iconName: "person.text.rectangle.fill", keywords: ["aadhaar", "aadhar", "identity", "id proof"]),
        MasterKYCSlot(id: "GST Certificate", title: "GST Registration Certificate", desc: "Form GST REG-06", iconName: "doc.plaintext.fill", keywords: ["gst", "gstin", "reg-06"]),
        MasterKYCSlot(id: "Cancelled Cheque", title: "Cancelled Cheque / Bank Proof", desc: "Bank account validation with IFSC & Acc No.", iconName: "building.columns.fill", keywords: ["cheque", "bank", "statement", "passbook"]),
        MasterKYCSlot(id: "Business Address Proof", title: "Business Address Proof", desc: "Electricity bill or rent agreement", iconName: "house.fill", keywords: ["address", "electricity", "bill", "rent", "noc"]),
        MasterKYCSlot(id: "Incorporation Certificate", title: "Certificate of Incorporation", desc: "MCA COI or Registration deed", iconName: "checkmark.seal.fill", keywords: ["incorporation", "coi", "deed", "registration cert"]),
        MasterKYCSlot(id: "MSME / Udyam Certificate", title: "MSME / Udyam Registration", desc: "Government MSME recognition certificate", iconName: "sparkles", keywords: ["msme", "udyam", "udyog"]),
        MasterKYCSlot(id: "MOA & AOA", title: "MOA & AOA / Partnership Deed", desc: "Charter documents and bylaws", iconName: "doc.on.doc.fill", keywords: ["moa", "aoa", "deed", "partnership", "charter"])
    ]
    
    private var orderFiles: [(name: String, url: String, source: String)] {
        var files: [(name: String, url: String, source: String)] = []
        for order in viewModel.orders {
            let orderTag = "Order #\(order.id.suffix(6).uppercased()) • \(order.serviceName)"
            for doc in order.clientDocuments {
                files.append((doc.name, doc.url, "Client Upload • \(orderTag)"))
            }
            for doc in order.adminDocuments {
                files.append((doc.name, doc.url, "Delivered Certificate • \(orderTag)"))
            }
            for req in order.customerRequirements {
                let url = !req.uploadedDocumentUrl.isEmpty ? req.uploadedDocumentUrl : (!req.documentUrl.isEmpty ? req.documentUrl : (req.value.hasPrefix("http") || req.value.hasPrefix("/uploads") ? req.value : ""))
                if !url.isEmpty {
                    files.append((!req.uploadedDocumentName.isEmpty ? req.uploadedDocumentName : req.title, url, "Requirement • \(orderTag)"))
                }
            }
        }
        return files
    }
    
    var body: some View {
        Group {
            if isEmbedded {
                vaultMainContent
            } else {
                ScrollView(showsIndicators: false) {
                    vaultMainContent
                        .padding(.bottom, 130)
                }
                .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
            }
        }
        .onAppear(perform: loadVaultDocs)
        .photosPicker(isPresented: $showPhotoPicker, selection: $selectedPhotoItem, matching: .images)
        .onChange(of: selectedPhotoItem) { newItem in
            guard let item = newItem, let slot = activeSlotForUpload else { return }
            isUploading = true
            Task {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    do {
                        _ = try await NetworkManager.shared.uploadUserVaultDocument(
                            docType: slot.id,
                            fileData: data,
                            fileName: "\(slot.id.replacingOccurrences(of: " ", with: "_")).jpg",
                            mimeType: "image/jpeg"
                        )
                        viewModel.toastMessage = "\(slot.title) uploaded to Vault!"
                        loadVaultDocs()
                    } catch {
                        viewModel.toastMessage = "Upload failed: \(error.localizedDescription)"
                    }
                }
                isUploading = false
                selectedPhotoItem = nil
                activeSlotForUpload = nil
            }
        }
        .fileImporter(isPresented: $showDocPicker, allowedContentTypes: [.pdf, .image, .data]) { result in
            guard let slot = activeSlotForUpload else { return }
            switch result {
            case .success(let fileUrl):
                guard fileUrl.startAccessingSecurityScopedResource() else { return }
                defer { fileUrl.stopAccessingSecurityScopedResource() }
                
                if let data = try? Data(contentsOf: fileUrl) {
                    isUploading = true
                    Task {
                        do {
                            _ = try await NetworkManager.shared.uploadUserVaultDocument(
                                docType: slot.id,
                                fileData: data,
                                fileName: fileUrl.lastPathComponent,
                                mimeType: fileUrl.pathExtension.lowercased() == "pdf" ? "application/pdf" : "image/jpeg"
                            )
                            viewModel.toastMessage = "\(slot.title) uploaded to Vault!"
                            loadVaultDocs()
                        } catch {
                            viewModel.toastMessage = "Upload failed: \(error.localizedDescription)"
                        }
                        isUploading = false
                        activeSlotForUpload = nil
                    }
                }
            case .failure(let error):
                viewModel.toastMessage = "File selection error: \(error.localizedDescription)"
            }
        }
        .actionSheet(isPresented: $showUploadOptions) {
            ActionSheet(
                title: Text("Upload \(activeSlotForUpload?.title ?? "Document")"),
                message: Text("Select source for official verification scan"),
                buttons: [
                    .default(Text("Choose from Photos")) { showPhotoPicker = true },
                    .default(Text("Browse PDF / Files")) { showDocPicker = true },
                    .cancel()
                ]
            )
        }
    }
    
    private var vaultMainContent: some View {
        VStack(spacing: 16) {
            // --- 1. HERO BANNER matching Android 1:1 ---
            ZStack {
                LinearGradient(
                    colors: [
                        Color(red: 30/255, green: 27/255, blue: 75/255),
                        Color(red: 49/255, green: 46/255, blue: 129/255),
                        Color(red: 67/255, green: 56/255, blue: 202/255)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("UPLOAD ONCE, USE ANYWHERE")
                            .font(.system(size: 9.5, weight: .black))
                            .foregroundColor(Color(red: 165/255, green: 180/255, blue: 252/255))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.3))
                            .clipShape(Capsule())
                        Spacer()
                    }
                    
                    Text("My Documents Vault")
                        .font(.system(size: 20, weight: .black))
                        .foregroundColor(.white)
                    
                    Text("Store your basic verification documents securely in our vault. They auto-populate across all your business service orders.")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(Color(red: 199/255, green: 210/255, blue: 254/255))
                        .lineSpacing(2)
                }
                .padding(18)
            }
            .cornerRadius(22)
            .padding(.horizontal, 16)
            .padding(.top, isEmbedded ? 0 : 12)
            
            // --- 2. SEGMENTED SECTION SWITCHER MATCHING ANDROID ---
            HStack(spacing: 0) {
                Button(action: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                        selectedSection = "Standard"
                    }
                }) {
                    Text("Standard Verification (\(kycSlots.count))")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(selectedSection == "Standard" ? .white : Color(red: 100/255, green: 116/255, blue: 139/255))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(selectedSection == "Standard" ? Color.primaryRed : Color.clear)
                        .cornerRadius(12)
                }
                
                Button(action: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                        selectedSection = "Deliverables"
                    }
                }) {
                    Text("Order Deliverables (\(orderFiles.count))")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(selectedSection == "Deliverables" ? .white : Color(red: 100/255, green: 116/255, blue: 139/255))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(selectedSection == "Deliverables" ? Color.primaryRed : Color.clear)
                        .cornerRadius(12)
                }
            }
            .padding(4)
            .background(Color.white)
            .cornerRadius(16)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
            .padding(.horizontal, 16)
            
            // --- 3. SECTION CONTENT ---
            if selectedSection == "Standard" {
                VStack(spacing: 12) {
                    ForEach(kycSlots) { slot in
                        let directVaultDoc = vaultDocuments.first(where: { $0.docType.caseInsensitiveCompare(slot.id) == .orderedSame })
                        let fallbackOrderFile = directVaultDoc == nil ? orderFiles.first(where: { file in
                            let lower = file.name.lowercased()
                            return slot.keywords.contains { kw in lower.contains(kw) }
                        }) : nil
                        
                        let isUploaded = directVaultDoc != nil
                        let isFromOrder = fallbackOrderFile != nil
                        let docUrl = directVaultDoc?.gdriveWebViewLink ?? fallbackOrderFile?.url ?? ""
                        let fileName = directVaultDoc?.fileName ?? fallbackOrderFile?.name ?? "Not uploaded yet"
                        
                        VStack(spacing: 12) {
                            HStack(alignment: .center, spacing: 10) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 12)
                                        .fill(isUploaded ? Color(red: 236/255, green: 253/255, blue: 245/255) : (isFromOrder ? Color(red: 239/255, green: 246/255, blue: 255/255) : Color(red: 241/255, green: 245/255, blue: 249/255)))
                                        .frame(width: 40, height: 40)
                                    Image(systemName: slot.iconName)
                                        .font(.system(size: 17))
                                        .foregroundColor(isUploaded ? Color(red: 4/255, green: 120/255, blue: 87/255) : (isFromOrder ? Color(red: 37/255, green: 99/255, blue: 235/255) : Color(red: 100/255, green: 116/255, blue: 139/255)))
                                }
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(slot.title)
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    Text(slot.desc)
                                        .font(.system(size: 11))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                }
                                
                                Spacer()
                                
                                Text(isUploaded ? "VERIFIED" : (isFromOrder ? "FROM ORDER" : "MISSING"))
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(isUploaded ? Color(red: 4/255, green: 120/255, blue: 87/255) : (isFromOrder ? Color(red: 29/255, green: 78/255, blue: 216/255) : Color(red: 180/255, green: 83/255, blue: 9/255)))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(isUploaded ? Color(red: 209/255, green: 250/255, blue: 229/255) : (isFromOrder ? Color(red: 219/255, green: 234/255, blue: 254/255) : Color(red: 254/255, green: 243/255, blue: 199/255)))
                                    .cornerRadius(6)
                            }
                            
                            if isUploaded || isFromOrder {
                                HStack(spacing: 6) {
                                    Text("📄 \(fileName)")
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                        .lineLimit(1)
                                    Spacer()
                                }
                                .padding(10)
                                .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                                .cornerRadius(10)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                            }
                            
                            HStack(spacing: 8) {
                                if !docUrl.isEmpty, let url = docUrl.asImageURL ?? URL(string: docUrl) {
                                    Button(action: { openURL(url) }) {
                                        HStack(spacing: 5) {
                                            Image(systemName: "eye.fill")
                                            Text("View Document")
                                        }
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(Color(red: 30/255, green: 41/255, blue: 59/255))
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 8)
                                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                        .cornerRadius(10)
                                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1))
                                    }
                                }
                                
                                Button(action: {
                                    activeSlotForUpload = slot
                                    showUploadOptions = true
                                }) {
                                    HStack(spacing: 5) {
                                        Image(systemName: "arrow.up.circle.fill")
                                        Text(isUploaded ? "Replace" : "Upload \(slot.id)")
                                    }
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(isUploaded ? Color(red: 15/255, green: 23/255, blue: 42/255) : Color.primaryRed)
                                    .cornerRadius(10)
                                }
                            }
                        }
                        .padding(14)
                        .background(Color.white)
                        .cornerRadius(18)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                        )
                        .padding(.horizontal, 16)
                    }
                }
            } else {
                // Deliverables Section
                if orderFiles.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "folder")
                            .font(.system(size: 44))
                            .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                        Text("No order deliverables found yet.")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        Text("Official certificates & uploads will automatically sync here.")
                            .font(.system(size: 11))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(36)
                    .background(Color.white)
                    .cornerRadius(20)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                    .padding(.horizontal, 16)
                } else {
                    VStack(spacing: 10) {
                        ForEach(0..<orderFiles.count, id: \.self) { idx in
                            let file = orderFiles[idx]
                            HStack(alignment: .center, spacing: 10) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 10)
                                        .fill(Color(red: 254/255, green: 242/255, blue: 242/255))
                                        .frame(width: 36, height: 36)
                                    Image(systemName: "doc.fill")
                                        .font(.system(size: 16))
                                        .foregroundColor(Color.primaryRed)
                                }
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(file.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        .lineLimit(1)
                                    Text(file.source)
                                        .font(.system(size: 10))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                        .lineLimit(1)
                                }
                                
                                Spacer()
                                
                                if let url = file.url.asImageURL ?? URL(string: file.url) {
                                    Button(action: { openURL(url) }) {
                                        Text("View")
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(.white)
                                            .padding(.horizontal, 12)
                                            .padding(.vertical, 6)
                                            .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .cornerRadius(8)
                                    }
                                }
                            }
                            .padding(12)
                            .background(Color.white)
                            .cornerRadius(16)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                            .padding(.horizontal, 16)
                        }
                    }
                }
            }
        }
    }
    
    private func loadVaultDocs() {
        Task {
            isLoading = true
            do {
                vaultDocuments = try await NetworkManager.shared.getUserVaultDocuments()
            } catch {
                print("Vault docs load error: \(error)")
            }
            isLoading = false
        }
    }
}
