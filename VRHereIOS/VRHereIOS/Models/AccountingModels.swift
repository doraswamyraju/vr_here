import Foundation

// MARK: - Transaction Item DTO

public struct TransactionItemDto: Codable, Identifiable, Equatable {
    public var id: String { description + (hsnSac ?? "") + "\(rate)_\(qty)" }
    public var description: String
    public var hsnSac: String?
    public var qty: Double
    public var unit: String?
    public var rate: Double
    public var discPercent: Double?
    public var taxableValue: Double
    public var gstRate: Double
    public var cgst: Double?
    public var sgst: Double?
    public var igst: Double?
    public var total: Double

    public init(
        description: String = "",
        hsnSac: String? = "998311",
        qty: Double = 1.0,
        unit: String? = "PCS",
        rate: Double = 0.0,
        discPercent: Double? = 0.0,
        taxableValue: Double = 0.0,
        gstRate: Double = 18.0,
        cgst: Double? = 0.0,
        sgst: Double? = 0.0,
        igst: Double? = 0.0,
        total: Double = 0.0
    ) {
        self.description = description
        self.hsnSac = hsnSac
        self.qty = qty
        self.unit = unit
        self.rate = rate
        self.discPercent = discPercent
        self.taxableValue = taxableValue
        self.gstRate = gstRate
        self.cgst = cgst
        self.sgst = sgst
        self.igst = igst
        self.total = total
    }

    enum CodingKeys: String, CodingKey {
        case description
        case hsnSac
        case qty
        case unit
        case rate
        case discPercent
        case taxableValue
        case gstRate
        case cgst
        case sgst
        case igst
        case total
    }
}

// MARK: - Transaction Summary DTO

public struct TransactionSummaryDto: Codable, Equatable {
    public var totalTaxableValue: Double
    public var totalCgst: Double
    public var totalSgst: Double
    public var totalIgst: Double
    public var roundOff: Double
    public var totalAmount: Double
    public var amountInWords: String?

    public init(
        totalTaxableValue: Double = 0.0,
        totalCgst: Double = 0.0,
        totalSgst: Double = 0.0,
        totalIgst: Double = 0.0,
        roundOff: Double = 0.0,
        totalAmount: Double = 0.0,
        amountInWords: String? = ""
    ) {
        self.totalTaxableValue = totalTaxableValue
        self.totalCgst = totalCgst
        self.totalSgst = totalSgst
        self.totalIgst = totalIgst
        self.roundOff = roundOff
        self.totalAmount = totalAmount
        self.amountInWords = amountInWords
    }

    enum CodingKeys: String, CodingKey {
        case totalTaxableValue
        case totalCgst
        case totalSgst
        case totalIgst
        case roundOff
        case totalAmount
        case amountInWords
    }
}

// MARK: - Transaction DTO

public struct TransactionDto: Codable, Identifiable, Equatable {
    public var id: String { _id ?? UUID().uuidString }
    public var _id: String?
    public var clientUser: String?
    public var transactionType: String // "Sales", "Purchase", "Expense", "Income", "CreditNote", "DebitNote"
    public var copyType: String?
    public var docNumber: String
    public var docDate: String
    public var dueDate: String?
    public var paymentMode: String // "Cash", "Bank Transfer", "UPI", "Cheque", "Credit"

    // Bill To
    public var partyName: String
    public var partyGstin: String?
    public var partyPan: String?
    public var partyAddress: String?
    public var partyState: String?
    public var partyPhone: String?
    public var partyEmail: String?
    public var placeOfSupply: String?
    public var isInterstate: Bool?

    // Ship To
    public var shipToSameAsBilling: Bool?
    public var shipToName: String?
    public var shipToAddress: String?
    public var shipToGstin: String?
    public var shipToPan: String?
    public var shipToState: String?
    public var shipToMobile: String?
    public var shipToEmail: String?

    // Line Items & Summary
    public var items: [TransactionItemDto]
    public var summary: TransactionSummaryDto

    public var itcEligibility: String? // "Inputs", "Input Services", "Capital Goods", "Ineligible", "N/A"
    public var paymentStatus: String // "Unpaid", "Partially Paid", "Paid"
    public var paidAmount: Double?
    public var status: String? // "Draft", "Recorded", "Verified", "Flagged"
    public var auditorNotes: String?
    public var notes: String?
    public var attachmentUrl: String?
    public var termsAndConditions: [String]?
    public var createdAt: String?
    public var updatedAt: String?

    public init(
        _id: String? = nil,
        clientUser: String? = nil,
        transactionType: String = "Sales",
        copyType: String? = "Original for Recipient",
        docNumber: String = "",
        docDate: String = "",
        dueDate: String? = nil,
        paymentMode: String = "Bank Transfer",
        partyName: String = "",
        partyGstin: String? = "",
        partyPan: String? = "",
        partyAddress: String? = "",
        partyState: String? = "",
        partyPhone: String? = "",
        partyEmail: String? = "",
        placeOfSupply: String? = "37-Andhra Pradesh",
        isInterstate: Bool? = false,
        shipToSameAsBilling: Bool? = true,
        shipToName: String? = "",
        shipToAddress: String? = "",
        shipToGstin: String? = "",
        shipToPan: String? = "",
        shipToState: String? = "",
        shipToMobile: String? = "",
        shipToEmail: String? = "",
        items: [TransactionItemDto] = [],
        summary: TransactionSummaryDto = TransactionSummaryDto(),
        itcEligibility: String? = "N/A",
        paymentStatus: String = "Unpaid",
        paidAmount: Double? = 0.0,
        status: String? = "Recorded",
        auditorNotes: String? = "",
        notes: String? = "",
        attachmentUrl: String? = "",
        termsAndConditions: [String]? = [],
        createdAt: String? = nil,
        updatedAt: String? = nil
    ) {
        self._id = _id
        self.clientUser = clientUser
        self.transactionType = transactionType
        self.copyType = copyType
        self.docNumber = docNumber
        self.docDate = docDate
        self.dueDate = dueDate
        self.paymentMode = paymentMode
        self.partyName = partyName
        self.partyGstin = partyGstin
        self.partyPan = partyPan
        self.partyAddress = partyAddress
        self.partyState = partyState
        self.partyPhone = partyPhone
        self.partyEmail = partyEmail
        self.placeOfSupply = placeOfSupply
        self.isInterstate = isInterstate
        self.shipToSameAsBilling = shipToSameAsBilling
        self.shipToName = shipToName
        self.shipToAddress = shipToAddress
        self.shipToGstin = shipToGstin
        self.shipToPan = shipToPan
        self.shipToState = shipToState
        self.shipToMobile = shipToMobile
        self.shipToEmail = shipToEmail
        self.items = items
        self.summary = summary
        self.itcEligibility = itcEligibility
        self.paymentStatus = paymentStatus
        self.paidAmount = paidAmount
        self.status = status
        self.auditorNotes = auditorNotes
        self.notes = notes
        self.attachmentUrl = attachmentUrl
        self.termsAndConditions = termsAndConditions
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case _id
        case clientUser
        case transactionType
        case copyType
        case docNumber
        case docDate
        case dueDate
        case paymentMode
        case partyName
        case partyGstin
        case partyPan
        case partyAddress
        case partyState
        case partyPhone
        case partyEmail
        case placeOfSupply
        case isInterstate
        case shipToSameAsBilling
        case shipToName
        case shipToAddress
        case shipToGstin
        case shipToPan
        case shipToState
        case shipToMobile
        case shipToEmail
        case items
        case summary
        case itcEligibility
        case paymentStatus
        case paidAmount
        case status
        case auditorNotes
        case notes
        case attachmentUrl
        case termsAndConditions
        case createdAt
        case updatedAt
    }
}

// MARK: - Party DTO

public struct PartyDto: Codable, Identifiable, Equatable {
    public var id: String { _id ?? UUID().uuidString }
    public var _id: String?
    public var partyType: String // "Customer", "Vendor", "Both"
    public var name: String
    public var tradeName: String?
    public var gstin: String?
    public var pan: String?
    public var email: String?
    public var phone: String?
    public var billingAddress: String?
    public var shippingAddress: String?
    public var state: String?
    public var pincode: String?
    public var openingBalance: Double?
    public var creditPeriodDays: Int?

    public init(
        _id: String? = nil,
        partyType: String = "Customer",
        name: String = "",
        tradeName: String? = "",
        gstin: String? = "",
        pan: String? = "",
        email: String? = "",
        phone: String? = "",
        billingAddress: String? = "",
        shippingAddress: String? = "",
        state: String? = "Andhra Pradesh",
        pincode: String? = "",
        openingBalance: Double? = 0.0,
        creditPeriodDays: Int? = 30
    ) {
        self._id = _id
        self.partyType = partyType
        self.name = name
        self.tradeName = tradeName
        self.gstin = gstin
        self.pan = pan
        self.email = email
        self.phone = phone
        self.billingAddress = billingAddress
        self.shippingAddress = shippingAddress
        self.state = state
        self.pincode = pincode
        self.openingBalance = openingBalance
        self.creditPeriodDays = creditPeriodDays
    }

    enum CodingKeys: String, CodingKey {
        case _id
        case partyType
        case name
        case tradeName
        case gstin
        case pan
        case email
        case phone
        case billingAddress
        case shippingAddress
        case state
        case pincode
        case openingBalance
        case creditPeriodDays
    }
}

// MARK: - Bank Transaction DTO

public struct BankTransactionDto: Codable, Identifiable, Equatable {
    public var id: String { _id ?? UUID().uuidString }
    public var _id: String?
    public var date: String
    public var description: String
    public var referenceNo: String?
    public var type: String // "DEBIT", "CREDIT"
    public var amount: Double
    public var balance: Double
    public var reconciliationStatus: String // "UNRECONCILED", "TAGGED", "EXCLUDED"
    public var taggedCategory: String?
    public var notes: String?

    public init(
        _id: String? = nil,
        date: String = "",
        description: String = "",
        referenceNo: String? = "",
        type: String = "CREDIT",
        amount: Double = 0.0,
        balance: Double = 0.0,
        reconciliationStatus: String = "UNRECONCILED",
        taggedCategory: String? = "",
        notes: String? = ""
    ) {
        self._id = _id
        self.date = date
        self.description = description
        self.referenceNo = referenceNo
        self.type = type
        self.amount = amount
        self.balance = balance
        self.reconciliationStatus = reconciliationStatus
        self.taggedCategory = taggedCategory
        self.notes = notes
    }

    enum CodingKeys: String, CodingKey {
        case _id
        case date
        case description
        case referenceNo
        case type
        case amount
        case balance
        case reconciliationStatus
        case taggedCategory
        case notes
    }
}

// MARK: - Bank Statement DTO

public struct BankStatementDto: Codable, Identifiable, Equatable {
    public var id: String { _id ?? UUID().uuidString }
    public var _id: String?
    public var bankName: String
    public var accountNumber: String
    public var statementTitle: String?
    public var fileName: String?
    public var fileUrl: String?
    public var transactions: [BankTransactionDto]
    public var createdAt: String?

    public init(
        _id: String? = nil,
        bankName: String = "",
        accountNumber: String = "",
        statementTitle: String? = "Bank Statement",
        fileName: String? = "",
        fileUrl: String? = "",
        transactions: [BankTransactionDto] = [],
        createdAt: String? = nil
    ) {
        self._id = _id
        self.bankName = bankName
        self.accountNumber = accountNumber
        self.statementTitle = statementTitle
        self.fileName = fileName
        self.fileUrl = fileUrl
        self.transactions = transactions
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case _id
        case bankName
        case accountNumber
        case statementTitle
        case fileName
        case fileUrl
        case transactions
        case createdAt
    }
}

// MARK: - Bank Account Details DTO

public struct BankAccountDetailsDto: Codable, Equatable {
    public var accountName: String?
    public var accountNumber: String?
    public var ifscCode: String?
    public var bankName: String?

    public init(
        accountName: String? = "",
        accountNumber: String? = "",
        ifscCode: String? = "",
        bankName: String? = ""
    ) {
        self.accountName = accountName
        self.accountNumber = accountNumber
        self.ifscCode = ifscCode
        self.bankName = bankName
    }

    enum CodingKeys: String, CodingKey {
        case accountName
        case accountNumber
        case ifscCode
        case bankName
    }
}

// MARK: - Company Details DTO

public struct CompanyDetailsDto: Codable, Identifiable, Equatable {
    public var id: String { _id ?? UUID().uuidString }
    public var _id: String?
    public var companyName: String?
    public var tradeName: String?
    public var gstin: String?
    public var address: String?
    public var state: String?
    public var phone: String?
    public var email: String?
    public var businessType: String?
    public var companyType: String?
    public var businessCategory: String?
    public var companyCategory: String?
    public var pincode: String?
    public var invoicePrefix: String?
    public var logo: String?
    public var signature: String?
    public var upiId: String?
    public var qrCode: String?
    public var bankDetails: BankAccountDetailsDto?

    public init(
        _id: String? = nil,
        companyName: String? = "",
        tradeName: String? = "",
        gstin: String? = "",
        address: String? = "",
        state: String? = "Andhra Pradesh",
        phone: String? = "",
        email: String? = "",
        businessType: String? = "Service",
        companyType: String? = "Service",
        businessCategory: String? = "",
        companyCategory: String? = "",
        pincode: String? = "",
        invoicePrefix: String? = "INV-",
        logo: String? = "",
        signature: String? = "",
        upiId: String? = "",
        qrCode: String? = "",
        bankDetails: BankAccountDetailsDto? = BankAccountDetailsDto()
    ) {
        self._id = _id
        self.companyName = companyName
        self.tradeName = tradeName
        self.gstin = gstin
        self.address = address
        self.state = state
        self.phone = phone
        self.email = email
        self.businessType = businessType
        self.companyType = companyType
        self.businessCategory = businessCategory
        self.companyCategory = companyCategory
        self.pincode = pincode
        self.invoicePrefix = invoicePrefix
        self.logo = logo
        self.signature = signature
        self.upiId = upiId
        self.qrCode = qrCode
        self.bankDetails = bankDetails
    }

    enum CodingKeys: String, CodingKey {
        case _id
        case companyName
        case tradeName
        case gstin
        case address
        case state
        case phone
        case email
        case businessType
        case companyType
        case businessCategory
        case companyCategory
        case pincode
        case invoicePrefix
        case logo
        case signature
        case upiId
        case qrCode
        case bankDetails
    }
}

// MARK: - Requests

public struct TagBankTransactionRequest: Codable {
    public var transactionId: String
    public var voucherId: String?
    public var category: String?
    public var notes: String?

    public init(
        transactionId: String,
        voucherId: String? = nil,
        category: String? = nil,
        notes: String? = nil
    ) {
        self.transactionId = transactionId
        self.voucherId = voucherId
        self.category = category
        self.notes = notes
    }
}

public struct RecordPaymentRequest: Codable {
    public var amount: Double
    public var paymentMode: String
    public var paymentDate: String?
    public var notes: String?

    public init(
        amount: Double,
        paymentMode: String = "Bank Transfer",
        paymentDate: String? = nil,
        notes: String? = nil
    ) {
        self.amount = amount
        self.paymentMode = paymentMode
        self.paymentDate = paymentDate
        self.notes = notes
    }
}
