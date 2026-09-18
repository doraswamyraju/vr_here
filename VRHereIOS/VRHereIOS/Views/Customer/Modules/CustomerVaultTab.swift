import SwiftUI
import PhotosUI

struct MasterKYCSlot: Identifiable {
    let id: String
    let title: String
    let desc: String
    let iconName: String
}

struct CustomerVaultTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    @Environment(\.openURL) private var openURL
    
    @State private var selectedTab = "Master KYC"
    @State private var vaultDocuments: [UserVaultDocument] = []
    @State private var isLoading = true
    
    // Photo Picker
    @State private var selectedSlot: MasterKYCSlot? = nil
    @State private var selectedPhotoItem: PhotosPickerItem? = nil
    @State private var isUploading = false
    @State private var searchQuery = ""
    
    private let kycSlots = [
        MasterKYCSlot(id: "PAN Card", title: "PAN Card (Director/Company)", desc: "Permanent Account Number proof", iconName: "creditcard.fill"),
        MasterKYCSlot(id: "Aadhaar Card", title: "Aadhaar Card (Director)", desc: "Identity & address verification", iconName: "person.text.rectangle.fill"),
        MasterKYCSlot(id: "GST Certificate", title: "GST Registration Certificate", desc: "Form GST REG-06", iconName: "doc.plaintext.fill"),
        MasterKYCSlot(id: "Cancelled Cheque", title: "Cancelled Cheque / Bank Proof", desc: "Bank account validation with IFSC & Acc No.", iconName: "building.columns.fill"),
        MasterKYCSlot(id: "Business Address Proof", title: "Business Address Proof", desc: "Electricity bill or rent agreement", iconName: "house.fill"),
        MasterKYCSlot(id: "Incorporation Certificate", title: "Certificate of Incorporation", desc: "MCA COI or Registration deed", iconName: "checkmark.seal.fill"),
        MasterKYCSlot(id: "MSME / Udyam Certificate", title: "MSME / Udyam Registration", desc: "Government MSME recognition certificate", iconName: "sparkles"),
        MasterKYCSlot(id: "MOA & AOA", title: "MOA & AOA / Partnership Deed", desc: "Charter documents and bylaws", iconName: "doc.on.doc.fill")
    ]
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 18) {
                // Header
                VStack(alignment: .leading, spacing: 4) {
                    Text("Document Vault & KYC")
                        .font(.system(size: 20, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Central repository for master business identity documents & deliverables.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Segmented Switcher
                Picker("Vault Category", selection: $selectedTab) {
                    Text("Master KYC (8)").tag("Master KYC")
                    Text("Order Deliverables").tag("Order Deliverables")
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(.horizontal, 20)
                
                if selectedTab == "Master KYC" {
                    // KYC Slots Section
                    VStack(spacing: 12) {
                        ForEach(kycSlots) { slot in
                            let existingDoc = vaultDocuments.first(where: { $0.docType.lowercased() == slot.id.lowercased() })
                            let isUploaded = existingDoc != nil
                            
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(alignment: .top, spacing: 12) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 12)
                                            .fill(isUploaded ? Color(red: 236/255, green: 253/255, blue: 245/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                            .frame(width: 42, height: 42)
                                        Image(systemName: slot.iconName)
                                            .font(.system(size: 18))
                                            .foregroundColor(isUploaded ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color(red: 100/255, green: 116/255, blue: 139/255))
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(slot.title)
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(.textDark)
                                        Text(slot.desc)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    
                                    Spacer()
                                    
                                    Text(isUploaded ? "VERIFIED" : "REQUIRED")
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(isUploaded ? Color(red: 6/255, green: 95/255, blue: 70/255) : Color(red: 146/255, green: 64/255, blue: 14/255))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(isUploaded ? Color(red: 209/255, green: 250/255, blue: 229/255) : Color(red: 254/255, green: 243/255, blue: 199/255))
                                        .cornerRadius(6)
                                }
                                
                                // File details & Actions
                                if let doc = existingDoc {
                                    HStack(spacing: 8) {
                                        Text("• \(doc.fileName)")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                            .lineLimit(1)
                                        
                                        Spacer()
                                        
                                        if let link = doc.gdriveWebViewLink, let url = URL(string: link) {
                                            Button(action: { openURL(url) }) {
                                                HStack(spacing: 4) {
                                                    Image(systemName: "eye.fill")
                                                    Text("View")
                                                }
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(.blue)
                                            }
                                        }
                                        
                                        Button(action: {
                                            selectedSlot = slot
                                        }) {
                                            Text("Replace")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        }
                                    }
                                    .padding(8)
                                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                    .cornerRadius(8)
                                } else {
                                    Button(action: {
                                        selectedSlot = slot
                                    }) {
                                        HStack {
                                            Image(systemName: "arrow.up.circle.fill")
                                            Text("Upload Document Photo / Scan")
                                        }
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 8)
                                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                        .cornerRadius(8)
                                    }
                                }
                            }
                            .padding(14)
                            .background(Color.white)
                            .cornerRadius(16)
                            .shadow(color: Color.black.opacity(0.03), radius: 6, y: 2)
                        }
                    }
                    .padding(.horizontal, 20)
                } else {
                    // Order Deliverables Section
                    let orderDocs = viewModel.orders.flatMap { order in
                        order.clientDocuments.map { ($0, "Upload • \(order.serviceName)") } +
                        order.adminDocuments.map { ($0, "Delivered Certificate • \(order.serviceName)") }
                    }
                    
                    if orderDocs.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "folder")
                                .font(.system(size: 40))
                                .foregroundColor(.gray.opacity(0.4))
                            Text("No order deliverables found")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 40)
                    } else {
                        VStack(spacing: 10) {
                            ForEach(0..<orderDocs.count, id: \.self) { idx in
                                let (doc, source) = orderDocs[idx]
                                HStack(spacing: 12) {
                                    Image(systemName: "doc.fill")
                                        .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                        .font(.title3)
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(doc.name)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.textDark)
                                            .lineLimit(1)
                                        Text(source)
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    Button(action: {
                                        if let url = getAbsoluteURL(path: doc.url) {
                                            openURL(url)
                                        }
                                    }) {
                                        Image(systemName: "arrow.down.circle.fill")
                                            .font(.title3)
                                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                    }
                                }
                                .padding(12)
                                .background(Color.white)
                                .cornerRadius(14)
                                .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
        .onAppear(perform: loadVaultDocs)
        .photosPicker(isPresented: Binding(
            get: { selectedSlot != nil },
            set: { if !$0 { selectedSlot = nil } }
        ), selection: $selectedPhotoItem, matching: .images)
        .onChange(of: selectedPhotoItem) { newItem in
            guard let item = newItem, let slot = selectedSlot else { return }
            Task {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    do {
                        _ = try await NetworkManager.shared.uploadUserVaultDocument(
                            docType: slot.id,
                            fileData: data,
                            fileName: "\(slot.id.replacingOccurrences(of: " ", with: "_")).jpg",
                            mimeType: "image/jpeg"
                        )
                        viewModel.toastMessage = "\(slot.title) uploaded to vault!"
                        loadVaultDocs()
                    } catch {
                        viewModel.toastMessage = "Upload failed: \(error.localizedDescription)"
                    }
                }
                selectedPhotoItem = nil
                selectedSlot = nil
            }
        }
    }
    
    private func loadVaultDocs() {
        isLoading = true
        Task {
            do {
                vaultDocuments = try await NetworkManager.shared.getUserVaultDocuments()
                isLoading = false
            } catch {
                isLoading = false
            }
        }
    }
}
