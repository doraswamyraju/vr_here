import SwiftUI
import PhotosUI

public struct CompanySettingsBottomSheet: View {
    public let currentDetails: CompanyDetailsDto?
    public let onDismiss: () -> Void
    public let onSubmit: (CompanyDetailsDto) -> Void

    @State private var companyName: String = ""
    @State private var tradeName: String = ""
    @State private var gstin: String = ""
    @State private var address: String = ""
    @State private var state: String = "Andhra Pradesh"
    @State private var phone: String = ""
    @State private var email: String = ""
    @State private var businessType: String = "Service"
    @State private var businessCategory: String = ""
    @State private var pincode: String = ""
    @State private var invoicePrefix: String = "INV-"
    @State private var upiId: String = ""

    // Media fields (Data URL / Image URL)
    @State private var logoUrl: String = ""
    @State private var signatureUrl: String = ""
    @State private var qrCodeUrl: String = ""

    // Bank details
    @State private var bankName: String = ""
    @State private var accountName: String = ""
    @State private var accountNumber: String = ""
    @State private var ifscCode: String = ""

    // Photo pickers
    @State private var selectedLogoItem: PhotosPickerItem? = nil
    @State private var selectedSignatureItem: PhotosPickerItem? = nil
    @State private var selectedQrItem: PhotosPickerItem? = nil

    private let indianStates = [
        "Andhra Pradesh", "Telangana", "Karnataka", "Tamil Nadu", "Maharashtra",
        "Delhi", "Gujarat", "Kerala", "Uttar Pradesh", "West Bengal", "Rajasthan",
        "Madhya Pradesh", "Punjab", "Haryana", "Bihar", "Odisha", "Assam", "Goa", "Uttarakhand", "Jharkhand"
    ]

    private let businessTypes = [
        "Service", "Retail", "Manufacturing", "Distributor", "Private Limited", "Proprietorship", "LLP", "Partnership"
    ]

    public init(
        currentDetails: CompanyDetailsDto?,
        onDismiss: @escaping () -> Void,
        onSubmit: @escaping (CompanyDetailsDto) -> Void
    ) {
        self.currentDetails = currentDetails
        self.onDismiss = onDismiss
        self.onSubmit = onSubmit
    }

    public var body: some View {
        NavigationView {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 18) {
                    // 1. Logo & Branding Header Card
                    HStack(spacing: 14) {
                        PhotosPicker(selection: $selectedLogoItem, matching: .images) {
                            ZStack {
                                Circle()
                                    .fill(Color.white)
                                    .frame(width: 68, height: 68)
                                    .overlay(Circle().stroke(Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1.5))

                                if !logoUrl.isEmpty {
                                    AsyncImage(url: URL(string: logoUrl)) { phase in
                                        if let image = phase.image {
                                            image.resizable().scaledToFill()
                                                .frame(width: 68, height: 68)
                                                .clipShape(Circle())
                                        } else {
                                            ProgressView()
                                        }
                                    }
                                } else {
                                    VStack(spacing: 2) {
                                        Image(systemName: "building.2.fill")
                                            .font(.system(size: 20))
                                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                        Text("Upload")
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    }
                                }
                            }
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Business Brand Logo")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text("Appears at top of GST Invoices and vouchers")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))

                            HStack(spacing: 8) {
                                PhotosPicker(selection: $selectedLogoItem, matching: .images) {
                                    Text(logoUrl.isEmpty ? "Choose Image" : "Change Logo")
                                        .font(.system(size: 10.5, weight: .bold))
                                        .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 4)
                                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                        .cornerRadius(6)
                                }

                                if !logoUrl.isEmpty {
                                    Button(action: { logoUrl = "" }) {
                                        Text("Remove")
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                    }
                                }
                            }
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )

                    // Invoice Prefix
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Invoice Number Prefix")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("INV-", text: $invoicePrefix)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    // Section 2: Business Details
                    Text("Business Information")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Business Legal Name *")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("e.g. Rajugari Ventures Pvt Ltd", text: $companyName)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Trade / Brand Name")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("Rajugari Ventures", text: $tradeName)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("GSTIN *")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("37ABCDE1234F1Z5", text: $gstin)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .textInputAutocapitalization(.characters)
                        }
                    }

                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Contact Phone")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("07997991101", text: $phone)
                                .keyboardType(.phonePad)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Billing Email")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("accounts@vrhere.in", text: $email)
                                .keyboardType(.emailAddress)
                                .textInputAutocapitalization(.never)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Business Type")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Picker("Type", selection: $businessType) {
                                ForEach(businessTypes, id: \.self) { t in
                                    Text(t).tag(t)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(8)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Category (e.g. IT)")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("IT / Consultancy", text: $businessCategory)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    // Section 3: Registered Address
                    Text("Location & Registered Address")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("State *")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Picker("State", selection: $state) {
                                ForEach(indianStates, id: \.self) { s in
                                    Text(s).tag(s)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(8)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Pincode")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("517501", text: $pincode)
                                .keyboardType(.numberPad)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Complete Office Address *")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextEditor(text: $address)
                            .frame(height: 60)
                            .padding(4)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                    }

                    // Section 4: Bank Account Details
                    Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                    Text("Bank Account Details (For Invoicing)")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Bank Name")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("HDFC Bank", text: $bankName)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Account Number")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("50200012345678", text: $accountNumber)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("IFSC Code")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("HDFC0001234", text: $ifscCode)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .textInputAutocapitalization(.characters)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("A/c Holder Name")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("Rajugari Ventures Pvt Ltd", text: $accountName)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    // Section 5: Payments & Signatures
                    Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                    Text("Payments & Signatures")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                    VStack(alignment: .leading, spacing: 4) {
                        Text("UPI ID (e.g. business@hdfcbank)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("business@hdfcbank", text: $upiId)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    HStack(spacing: 12) {
                        // QR Code Picker
                        PhotosPicker(selection: $selectedQrItem, matching: .images) {
                            VStack(spacing: 6) {
                                if !qrCodeUrl.isEmpty {
                                    AsyncImage(url: URL(string: qrCodeUrl)) { phase in
                                        if let img = phase.image {
                                            img.resizable().scaledToFit().frame(height: 50)
                                        } else {
                                            ProgressView()
                                        }
                                    }
                                    Text("Payment QR Attached")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                } else {
                                    Image(systemName: "qrcode")
                                        .font(.system(size: 24))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Text("Upload QR Image")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(14)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                        }

                        // Signature Picker
                        PhotosPicker(selection: $selectedSignatureItem, matching: .images) {
                            VStack(spacing: 6) {
                                if !signatureUrl.isEmpty {
                                    AsyncImage(url: URL(string: signatureUrl)) { phase in
                                        if let img = phase.image {
                                            img.resizable().scaledToFit().frame(height: 50)
                                        } else {
                                            ProgressView()
                                        }
                                    }
                                    Text("Signature Attached")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                                } else {
                                    Image(systemName: "signature")
                                        .font(.system(size: 24))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Text("Upload Signature")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(14)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(12)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1))
                        }
                    }

                    // Save Button
                    Button(action: {
                        guard !companyName.trimmingCharacters(in: .whitespaces).isEmpty && !gstin.trimmingCharacters(in: .whitespaces).isEmpty else { return }

                        let updated = CompanyDetailsDto(
                            _id: currentDetails?._id,
                            companyName: companyName.trimmingCharacters(in: .whitespaces),
                            tradeName: tradeName.trimmingCharacters(in: .whitespaces),
                            gstin: gstin.trimmingCharacters(in: .whitespaces).uppercased(),
                            address: address.trimmingCharacters(in: .whitespaces),
                            state: state.trimmingCharacters(in: .whitespaces),
                            phone: phone.trimmingCharacters(in: .whitespaces),
                            email: email.trimmingCharacters(in: .whitespaces),
                            businessType: businessType.trimmingCharacters(in: .whitespaces),
                            companyType: businessType.trimmingCharacters(in: .whitespaces),
                            businessCategory: businessCategory.trimmingCharacters(in: .whitespaces),
                            companyCategory: businessCategory.trimmingCharacters(in: .whitespaces),
                            pincode: pincode.trimmingCharacters(in: .whitespaces),
                            invoicePrefix: invoicePrefix.trimmingCharacters(in: .whitespaces),
                            logo: logoUrl,
                            signature: signatureUrl,
                            upiId: upiId.trimmingCharacters(in: .whitespaces),
                            qrCode: qrCodeUrl,
                            bankDetails: BankAccountDetailsDto(
                                accountName: accountName.trimmingCharacters(in: .whitespaces).isEmpty ? companyName.trimmingCharacters(in: .whitespaces) : accountName.trimmingCharacters(in: .whitespaces),
                                accountNumber: accountNumber.trimmingCharacters(in: .whitespaces),
                                ifscCode: ifscCode.trimmingCharacters(in: .whitespaces).uppercased(),
                                bankName: bankName.trimmingCharacters(in: .whitespaces)
                            )
                        )
                        onSubmit(updated)
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark")
                                .font(.system(size: 14, weight: .bold))
                            Text("Save Company & Bank Settings")
                                .font(.system(size: 14, weight: .bold))
                        }
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                        .cornerRadius(12)
                    }

                    Spacer().frame(height: 20)
                }
                .padding(20)
            }
            .navigationTitle("Company Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cancel", action: onDismiss)
                }
            }
        }
        .onAppear {
            if let details = currentDetails {
                companyName = details.companyName ?? ""
                tradeName = details.tradeName ?? ""
                gstin = details.gstin ?? ""
                address = details.address ?? ""
                state = details.state ?? "Andhra Pradesh"
                phone = details.phone ?? ""
                email = details.email ?? ""
                businessType = details.businessType ?? "Service"
                businessCategory = details.businessCategory ?? ""
                pincode = details.pincode ?? ""
                invoicePrefix = details.invoicePrefix ?? "INV-"
                upiId = details.upiId ?? ""
                logoUrl = details.logo ?? ""
                signatureUrl = details.signature ?? ""
                qrCodeUrl = details.qrCode ?? ""

                if let bank = details.bankDetails {
                    bankName = bank.bankName ?? ""
                    accountName = bank.accountName ?? ""
                    accountNumber = bank.accountNumber ?? ""
                    ifscCode = bank.ifscCode ?? ""
                }
            }
        }
        .onChange(of: selectedLogoItem) { newItem in
            Task {
                if let data = try? await newItem?.loadTransferable(type: Data.self) {
                    let base64 = "data:image/jpeg;base64," + data.base64EncodedString()
                    logoUrl = base64
                }
            }
        }
        .onChange(of: selectedSignatureItem) { newItem in
            Task {
                if let data = try? await newItem?.loadTransferable(type: Data.self) {
                    let base64 = "data:image/jpeg;base64," + data.base64EncodedString()
                    signatureUrl = base64
                }
            }
        }
        .onChange(of: selectedQrItem) { newItem in
            Task {
                if let data = try? await newItem?.loadTransferable(type: Data.self) {
                    let base64 = "data:image/jpeg;base64," + data.base64EncodedString()
                    qrCodeUrl = base64
                }
            }
        }
    }
}
