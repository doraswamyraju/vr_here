import SwiftUI
import PhotosUI
import Vision

struct CustomerBookkeepingTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    @State private var selectedTab = "Sales" // "Sales" or "Purchases"
    @State private var showingAddForm = false
    @State private var showingSettings = false
    
    // Form fields
    @State private var docNumber = ""
    @State private var docDate = Date()
    @State private var partyName = ""
    @State private var partyGstin = ""
    @State private var placeOfSupply = "Andhra Pradesh"
    @State private var isInterstate = false
    @State private var itcEligibility = "Inputs"
    @State private var notes = ""
    
    // OCR fields
    @State private var selectedItem: PhotosPickerItem? = nil
    @State private var isScanning = false
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header details
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Bookkeeping Hub")
                            .font(.title2)
                            .bold()
                            .foregroundColor(.primary)
                        Text("Manage your sales, purchases, and invoices locally.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    
                    Button(action: { showingSettings = true }) {
                        Image(systemName: "gearshape")
                            .font(.body)
                            .padding(10)
                            .background(Color.secondary.opacity(0.1))
                            .cornerRadius(12)
                    }
                }
                .padding(.horizontal)
                .padding(.top)

                // Stats Dashboard
                HStack(spacing: 12) {
                    VStack(alignment: .leading) {
                        Text("Sales")
                            .font(.caption2)
                            .bold()
                            .foregroundColor(.gray)
                        Text("₹45,250")
                            .font(.headline)
                            .bold()
                            .foregroundColor(.green)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color.green.opacity(0.05))
                    .cornerRadius(16)
                    
                    VStack(alignment: .leading) {
                        Text("Purchases")
                            .font(.caption2)
                            .bold()
                            .foregroundColor(.gray)
                        Text("₹12,400")
                            .font(.headline)
                            .bold()
                            .foregroundColor(.blue)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color.blue.opacity(0.05))
                    .cornerRadius(16)
                }
                .padding(.horizontal)

                // Segment Control
                Picker("Bookkeeping Type", selection: $selectedTab) {
                    Text("Sales").tag("Sales")
                    Text("Purchases").tag("Purchases")
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(.horizontal)

                // Action buttons
                HStack(spacing: 12) {
                    Button(action: { showingAddForm = true }) {
                        HStack {
                            Image(systemName: "plus")
                            Text("Record Transaction")
                        }
                        .bold()
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(16)
                    }
                }
                .padding(.horizontal)

                // Lists placeholder
                VStack(spacing: 12) {
                    HStack {
                        Text("Recent Vouchers")
                            .font(.subheadline)
                            .bold()
                        Spacer()
                    }
                    .padding(.horizontal)
                    
                    // Display mock items
                    VStack(spacing: 12) {
                        VoucherRow(type: "Sales", number: "INV-2026-001", date: "13 Jul 2026", amount: "₹24,500", party: "Raju Ventures Ltd")
                        VoucherRow(type: "Purchase", number: "PUR-98212", date: "10 Jul 2026", amount: "₹8,300", party: "Andhra Cement Stores")
                        VoucherRow(type: "Sales", number: "INV-2026-002", date: "09 Jul 2026", amount: "₹20,750", party: "Krishna Tech Services")
                    }
                    .padding(.horizontal)
                }
            }
        }
        .sheet(isPresented: $showingAddForm) {
            AddTransactionSheet(
                selectedTab: $selectedTab,
                docNumber: $docNumber,
                docDate: $docDate,
                partyName: $partyName,
                partyGstin: $partyGstin,
                placeOfSupply: $placeOfSupply,
                isInterstate: $isInterstate,
                itcEligibility: $itcEligibility,
                notes: $notes,
                selectedItem: $selectedItem,
                isScanning: $isScanning,
                onSave: {
                    // Perform save
                    showingAddForm = false
                }
            )
        }
        .sheet(isPresented: $showingSettings) {
            CompanySettingsSheet(onSave: { showingSettings = false })
        }
    }
}

struct VoucherRow: View {
    let type: String
    let number: String
    let date: String
    let amount: String
    let party: String
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(type)
                        .font(.caption2)
                        .bold()
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(type == "Sales" ? Color.green.opacity(0.1) : Color.blue.opacity(0.1))
                        .foregroundColor(type == "Sales" ? .green : .blue)
                        .cornerRadius(6)
                    
                    Text(number)
                        .font(.subheadline)
                        .bold()
                }
                
                Text(party)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            
            VStack(alignment: .trailing, spacing: 4) {
                Text(amount)
                    .font(.subheadline)
                    .bold()
                Text(date)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.02), radius: 5, x: 0, y: 2)
    }
}

struct AddTransactionSheet: View {
    @Binding var selectedTab: String
    @Binding var docNumber: String
    @Binding var docDate: Date
    @Binding var partyName: String
    @Binding var partyGstin: String
    @Binding var placeOfSupply: String
    @Binding var isInterstate: Bool
    @Binding var itcEligibility: String
    @Binding var notes: String
    
    @Binding var selectedItem: PhotosPickerItem?
    @Binding var isScanning: Bool
    
    let onSave: () -> Void
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("OCR Scan Bill (For Purchases)")) {
                    PhotosPicker(selection: $selectedItem, matching: .images) {
                        HStack {
                            Image(systemName: "camera.viewfinder")
                            Text(isScanning ? "Scanning image..." : "Upload Bill & Scan (Vision OCR)")
                        }
                        .bold()
                        .foregroundColor(.blue)
                    }
                    .onChange(of: selectedItem) { newItem in
                        if let newItem = newItem {
                            isScanning = true
                            Task {
                                if let data = try? await newItem.loadTransferable(type: Data.self),
                                   let image = UIImage(data: data) {
                                    recognizeText(in: image)
                                }
                                isScanning = false
                            }
                        }
                    }
                }
                
                Section(header: Text("Voucher Details")) {
                    Picker("Type", selection: $selectedTab) {
                        Text("Sales").tag("Sales")
                        Text("Purchases").tag("Purchases")
                    }
                    .pickerStyle(SegmentedPickerStyle())
                    
                    TextField("Document Number", text: $docNumber)
                    DatePicker("Date", selection: $docDate, displayedComponents: .date)
                    TextField("Party Name", text: $partyName)
                    TextField("Party GSTIN", text: $partyGstin)
                }
                
                Section(header: Text("Tax Configuration")) {
                    Picker("Place of Supply", selection: $placeOfSupply) {
                        Text("Andhra Pradesh").tag("Andhra Pradesh")
                        Text("Telangana").tag("Telangana")
                        Text("Karnataka").tag("Karnataka")
                    }
                    Toggle("Is Interstate (IGST)", isOn: $isInterstate)
                    
                    if selectedTab == "Purchases" {
                        Picker("ITC Eligibility", selection: $itcEligibility) {
                            Text("Inputs").tag("Inputs")
                            Text("Input Services").tag("Input Services")
                            Text("Capital Goods").tag("Capital Goods")
                            Text("Ineligible").tag("Ineligible")
                        }
                    }
                }
                
                Section(header: Text("Notes")) {
                    TextField("Add notes here...", text: $notes)
                }
            }
            .navigationTitle("Record Entry")
            .navigationBarItems(
                leading: Button("Cancel") { onSave() },
                trailing: Button("Save") { onSave() }.bold()
            )
        }
    }
    
    // On-device text recognition using Vision Framework
    private func recognizeText(in image: UIImage) {
        guard let cgImage = image.cgImage else { return }
        
        let requestHandler = VNImageRequestHandler(cgImage: cgImage, options: [:])
        let request = VNRecognizeTextRequest { request, error in
            guard let observations = request.results as? [VNRecognizedTextObservation] else { return }
            
            var fullText = ""
            for observation in observations {
                if let candidate = observation.topCandidates(1).first {
                    fullText += candidate.string + "\n"
                }
            }
            
            // Basic parsing logic
            DispatchQueue.main.async {
                // Look for GSTIN pattern
                if let range = fullText.range(of: #"\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}"#, options: .regularExpression) {
                    self.partyGstin = String(fullText[range])
                }
                // Mock doc details for demo
                self.partyName = "Scanned Vendor"
                self.docNumber = "SCN-" + String(Int.random(in: 1000...9999))
            }
        }
        
        request.recognitionLevel = .accurate
        try? requestHandler.perform([request])
    }
}

struct CompanySettingsSheet: View {
    @State private var companyName = ""
    @State private var tradeName = ""
    @State private var gstin = ""
    @State private var address = ""
    
    let onSave: () -> Void
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Company Metadata")) {
                    TextField("Legal Name", text: $companyName)
                    TextField("Trade Name", text: $tradeName)
                    TextField("GSTIN", text: $gstin)
                    TextField("Billing Address", text: $address)
                }
            }
            .navigationTitle("Company Profile")
            .navigationBarItems(
                leading: Button("Cancel") { onSave() },
                trailing: Button("Save") { onSave() }.bold()
            )
        }
    }
}
