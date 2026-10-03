import SwiftUI
import Contacts
import ContactsUI

public struct PartyFormBottomSheet: View {
    public let existingParty: PartyDto?
    public let onDismiss: () -> Void
    public let onSubmit: (PartyDto) -> Void

    @State private var partyType: String = "Customer"
    @State private var name: String = ""
    @State private var tradeName: String = ""
    @State private var gstin: String = ""
    @State private var pan: String = ""
    @State private var phone: String = ""
    @State private var email: String = ""
    @State private var billingAddress: String = ""
    @State private var state: String = "Andhra Pradesh"
    @State private var pincode: String = ""

    @State private var showContactPicker: Bool = false

    public init(
        existingParty: PartyDto? = nil,
        onDismiss: @escaping () -> Void,
        onSubmit: @escaping (PartyDto) -> Void
    ) {
        self.existingParty = existingParty
        self.onDismiss = onDismiss
        self.onSubmit = onSubmit
    }

    public var body: some View {
        NavigationView {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 16) {
                    // Quick Import Banner Button
                    Button(action: { showContactPicker = true }) {
                        HStack {
                            HStack(spacing: 8) {
                                Image(systemName: "person.crop.circle.badge.plus")
                                    .font(.system(size: 16))
                                    .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Select from Phone Contacts")
                                        .font(.system(size: 12.5, weight: .bold))
                                        .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                    Text("Auto-fill name & phone number from address book")
                                        .font(.system(size: 10.5))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                }
                            }
                            Spacer()
                            Text("Select →")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                        }
                        .padding(12)
                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color(red: 199/255, green: 210/255, blue: 254/255), lineWidth: 1)
                        )
                    }

                    // Party Type Selector
                    HStack(spacing: 8) {
                        ForEach(["Customer", "Vendor", "Both"], id: \.self) { t in
                            let isSel = partyType == t
                            Button(action: { partyType = t }) {
                                Text(t)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(isSel ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                    .cornerRadius(10)
                            }
                        }
                    }

                    // Legal Name
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Legal Entity / Party Name *")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("e.g. Apex Digital Solutions Pvt Ltd", text: $name)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    // Trade Name
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Trade Name (Optional)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("e.g. Apex Digital", text: $tradeName)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    // GSTIN & PAN
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("GSTIN")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("37AABCA4589D1Z3", text: $gstin)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .textInputAutocapitalization(.characters)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("PAN")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("AABCA4589D", text: $pan)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .textInputAutocapitalization(.characters)
                        }
                    }

                    // Phone & Email
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Phone / Mobile")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("+91 9876543210", text: $phone)
                                .keyboardType(.phonePad)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Email Address")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("billing@apex.in", text: $email)
                                .keyboardType(.emailAddress)
                                .textInputAutocapitalization(.never)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    // Billing Address
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Billing Address")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("Street address, building, floor", text: $billingAddress)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    // State & Pincode
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("State")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("Andhra Pradesh", text: $state)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
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

                    // Save Button
                    Button(action: {
                        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { return }

                        let party = PartyDto(
                            _id: existingParty?._id,
                            partyType: partyType,
                            name: name.trimmingCharacters(in: .whitespaces),
                            tradeName: tradeName.trimmingCharacters(in: .whitespaces),
                            gstin: gstin.trimmingCharacters(in: .whitespaces).uppercased(),
                            pan: pan.trimmingCharacters(in: .whitespaces).uppercased(),
                            email: email.trimmingCharacters(in: .whitespaces),
                            phone: phone.trimmingCharacters(in: .whitespaces),
                            billingAddress: billingAddress.trimmingCharacters(in: .whitespaces),
                            state: state.trimmingCharacters(in: .whitespaces),
                            pincode: pincode.trimmingCharacters(in: .whitespaces)
                        )
                        onSubmit(party)
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark")
                                .font(.system(size: 14, weight: .bold))
                            Text(existingParty != nil ? "Update Party Record" : "Save to Master Directory")
                                .font(.system(size: 14, weight: .bold))
                        }
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                        .cornerRadius(12)
                    }

                    // Save to Phone Contacts Action
                    if !name.isEmpty && !phone.isEmpty {
                        Button(action: saveToContacts) {
                            HStack(spacing: 6) {
                                Image(systemName: "person.badge.plus")
                                    .font(.system(size: 13))
                                Text("Save Party to Phone Contacts")
                                    .font(.system(size: 13, weight: .semibold))
                            }
                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                            .cornerRadius(12)
                        }
                    }

                    Spacer().frame(height: 20)
                }
                .padding(20)
            }
            .navigationTitle(existingParty != nil ? "Edit Party" : "Add Party")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cancel", action: onDismiss)
                }
            }
        }
        .sheet(isPresented: $showContactPicker) {
            CNContactPickerBridge { pickedName, pickedPhone, pickedEmail in
                if !pickedName.isEmpty { name = pickedName }
                if !pickedPhone.isEmpty { phone = pickedPhone }
                if !pickedEmail.isEmpty { email = pickedEmail }
                showContactPicker = false
            }
        }
        .onAppear {
            if let existing = existingParty {
                partyType = existing.partyType
                name = existing.name
                tradeName = existing.tradeName ?? ""
                gstin = existing.gstin ?? ""
                pan = existing.pan ?? ""
                phone = existing.phone ?? ""
                email = existing.email ?? ""
                billingAddress = existing.billingAddress ?? ""
                state = existing.state ?? "Andhra Pradesh"
                pincode = existing.pincode ?? ""
            }
        }
    }

    private func saveToContacts() {
        let store = CNContactStore()
        store.requestAccess(for: .contacts) { granted, _ in
            guard granted else { return }
            let contact = CNMutableContact()
            contact.givenName = name
            contact.organizationName = tradeName.isEmpty ? name : tradeName
            if !phone.isEmpty {
                contact.phoneNumbers = [CNLabeledValue(label: CNLabelWork, value: CNPhoneNumber(stringValue: phone))]
            }
            if !email.isEmpty {
                contact.emailAddresses = [CNLabeledValue(label: CNLabelWork, value: email as NSString)]
            }
            if !billingAddress.isEmpty {
                let postal = CNMutablePostalAddress()
                postal.street = billingAddress
                postal.state = state
                postal.postalCode = pincode
                postal.country = "India"
                contact.postalAddresses = [CNLabeledValue(label: CNLabelWork, value: postal)]
            }
            let req = CNSaveRequest()
            req.add(contact, toContainerWithIdentifier: nil)
            _ = try? store.execute(req)
        }
    }
}

// MARK: - Native Contact Picker Bridge

struct CNContactPickerBridge: UIViewControllerRepresentable {
    var onSelect: (String, String, String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIViewController(context: Context) -> CNContactPickerViewController {
        let picker = CNContactPickerViewController()
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: CNContactPickerViewController, context: Context) {}

    class Coordinator: NSObject, CNContactPickerDelegate {
        var parent: CNContactPickerBridge
        init(_ parent: CNContactPickerBridge) { self.parent = parent }

        func contactPicker(_ picker: CNContactPickerViewController, didSelect contact: CNContact) {
            let fullName = "\(contact.givenName) \(contact.familyName)".trimmingCharacters(in: .whitespaces)
            let phone = contact.phoneNumbers.first?.value.stringValue ?? ""
            let email = (contact.emailAddresses.first?.value as String?) ?? ""
            DispatchQueue.main.async {
                self.parent.onSelect(fullName, phone, email)
            }
        }
    }
}
