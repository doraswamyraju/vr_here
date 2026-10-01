package com.sbr.vrherebms.data.model

import com.google.gson.annotations.SerializedName

// --- TRANSACTION MODELS ---

data class TransactionItemDto(
    @SerializedName("description") val description: String = "",
    @SerializedName("hsnSac") val hsnSac: String = "",
    @SerializedName("qty") val qty: Double = 1.0,
    @SerializedName("unit") val unit: String = "PCS",
    @SerializedName("rate") val rate: Double = 0.0,
    @SerializedName("discPercent") val discPercent: Double = 0.0,
    @SerializedName("taxableValue") val taxableValue: Double = 0.0,
    @SerializedName("gstRate") val gstRate: Double = 18.0,
    @SerializedName("cgst") val cgst: Double = 0.0,
    @SerializedName("sgst") val sgst: Double = 0.0,
    @SerializedName("igst") val igst: Double = 0.0,
    @SerializedName("total") val total: Double = 0.0
)

data class TransactionSummaryDto(
    @SerializedName("totalTaxableValue") val totalTaxableValue: Double = 0.0,
    @SerializedName("totalCgst") val totalCgst: Double = 0.0,
    @SerializedName("totalSgst") val totalSgst: Double = 0.0,
    @SerializedName("totalIgst") val totalIgst: Double = 0.0,
    @SerializedName("roundOff") val roundOff: Double = 0.0,
    @SerializedName("totalAmount") val totalAmount: Double = 0.0,
    @SerializedName("amountInWords") val amountInWords: String = ""
)

data class TransactionDto(
    @SerializedName("_id") val id: String = "",
    @SerializedName("clientUser") val clientUser: String = "",
    @SerializedName("transactionType") val transactionType: String = "Sales", // Sales, Purchase, Income, Expense, CreditNote, DebitNote
    @SerializedName("copyType") val copyType: String = "Original for Recipient",
    @SerializedName("docNumber") val docNumber: String = "",
    @SerializedName("docDate") val docDate: String = "",
    @SerializedName("dueDate") val dueDate: String? = null,
    @SerializedName("paymentMode") val paymentMode: String = "Bank Transfer", // Cash, Bank Transfer, UPI, Cheque, Credit
    
    // Bill To (Customer / Vendor)
    @SerializedName("partyName") val partyName: String = "",
    @SerializedName("partyGstin") val partyGstin: String = "",
    @SerializedName("partyPan") val partyPan: String = "",
    @SerializedName("partyAddress") val partyAddress: String = "",
    @SerializedName("partyState") val partyState: String = "",
    @SerializedName("partyPhone") val partyPhone: String = "",
    @SerializedName("partyEmail") val partyEmail: String = "",
    @SerializedName("placeOfSupply") val placeOfSupply: String = "37-Andhra Pradesh",
    @SerializedName("isInterstate") val isInterstate: Boolean = false,
    
    // Ship To (Consignee)
    @SerializedName("shipToSameAsBilling") val shipToSameAsBilling: Boolean = true,
    @SerializedName("shipToName") val shipToName: String = "",
    @SerializedName("shipToAddress") val shipToAddress: String = "",
    @SerializedName("shipToGstin") val shipToGstin: String = "",
    @SerializedName("shipToPan") val shipToPan: String = "",
    @SerializedName("shipToState") val shipToState: String = "",
    @SerializedName("shipToMobile") val shipToMobile: String = "",
    @SerializedName("shipToEmail") val shipToEmail: String = "",
    
    // Line Items & Summary
    @SerializedName("items") val items: List<TransactionItemDto> = emptyList(),
    @SerializedName("summary") val summary: TransactionSummaryDto = TransactionSummaryDto(),
    
    @SerializedName("itcEligibility") val itcEligibility: String = "N/A", // Inputs, Input Services, Capital Goods, Ineligible, N/A
    @SerializedName("paymentStatus") val paymentStatus: String = "Unpaid", // Unpaid, Partially Paid, Paid
    @SerializedName("paidAmount") val paidAmount: Double = 0.0,
    @SerializedName("status") val status: String = "Recorded", // Draft, Recorded, Verified, Flagged
    @SerializedName("auditorNotes") val auditorNotes: String = "",
    @SerializedName("notes") val notes: String = "",
    @SerializedName("attachmentUrl") val attachmentUrl: String = "",
    @SerializedName("termsAndConditions") val termsAndConditions: List<String> = emptyList(),
    @SerializedName("createdAt") val createdAt: String = "",
    @SerializedName("updatedAt") val updatedAt: String = ""
)

// --- PARTY (CUSTOMER / VENDOR) MODELS ---

data class PartyDto(
    @SerializedName("_id") val id: String = "",
    @SerializedName("partyType") val partyType: String = "Customer", // Customer, Vendor, Both
    @SerializedName("name") val name: String = "",
    @SerializedName("tradeName") val tradeName: String = "",
    @SerializedName("gstin") val gstin: String = "",
    @SerializedName("pan") val pan: String = "",
    @SerializedName("email") val email: String = "",
    @SerializedName("phone") val phone: String = "",
    @SerializedName("billingAddress") val billingAddress: String = "",
    @SerializedName("shippingAddress") val shippingAddress: String = "",
    @SerializedName("state") val state: String = "Andhra Pradesh",
    @SerializedName("pincode") val pincode: String = "",
    @SerializedName("openingBalance") val openingBalance: Double = 0.0,
    @SerializedName("creditPeriodDays") val creditPeriodDays: Int = 30
)

// --- BANK STATEMENT & TRANSACTION LINE MODELS ---

data class BankTransactionDto(
    @SerializedName("_id") val id: String = "",
    @SerializedName("date") val date: String = "",
    @SerializedName("description") val description: String = "",
    @SerializedName("referenceNo") val referenceNo: String = "",
    @SerializedName("type") val type: String = "CREDIT", // DEBIT, CREDIT
    @SerializedName("amount") val amount: Double = 0.0,
    @SerializedName("balance") val balance: Double = 0.0,
    @SerializedName("reconciliationStatus") val reconciliationStatus: String = "UNRECONCILED", // UNRECONCILED, TAGGED, EXCLUDED
    @SerializedName("taggedVoucher") val taggedVoucher: Any? = null,
    @SerializedName("taggedCategory") val taggedCategory: String = "",
    @SerializedName("notes") val notes: String = ""
)

data class BankStatementDto(
    @SerializedName("_id") val id: String = "",
    @SerializedName("bankName") val bankName: String = "",
    @SerializedName("accountNumber") val accountNumber: String = "",
    @SerializedName("statementTitle") val statementTitle: String = "Bank Statement",
    @SerializedName("fileName") val fileName: String = "",
    @SerializedName("fileUrl") val fileUrl: String = "",
    @SerializedName("transactions") val transactions: List<BankTransactionDto> = emptyList(),
    @SerializedName("createdAt") val createdAt: String = ""
)

// --- COMPANY DETAILS & PROFILE ---

data class BankAccountDetailsDto(
    @SerializedName("accountName") val accountName: String = "",
    @SerializedName("accountNumber") val accountNumber: String = "",
    @SerializedName("ifscCode") val ifscCode: String = "",
    @SerializedName("bankName") val bankName: String = ""
)

data class CompanyDetailsDto(
    @SerializedName("_id") val id: String = "",
    @SerializedName("companyName") val companyName: String = "",
    @SerializedName("tradeName") val tradeName: String = "",
    @SerializedName("gstin") val gstin: String = "",
    @SerializedName("address") val address: String = "",
    @SerializedName("state") val state: String = "Andhra Pradesh",
    @SerializedName("phone") val phone: String = "",
    @SerializedName("email") val email: String = "",
    @SerializedName("businessType") val businessType: String = "Service",
    @SerializedName("companyType") val companyType: String = "Service",
    @SerializedName("businessCategory") val businessCategory: String = "",
    @SerializedName("companyCategory") val companyCategory: String = "",
    @SerializedName("pincode") val pincode: String = "",
    @SerializedName("invoicePrefix") val invoicePrefix: String = "INV-",
    @SerializedName("logo") val logo: String = "",
    @SerializedName("signature") val signature: String = "",
    @SerializedName("upiId") val upiId: String = "",
    @SerializedName("qrCode") val qrCode: String = "",
    @SerializedName("bankDetails") val bankDetails: BankAccountDetailsDto = BankAccountDetailsDto()
)

// --- REQUEST PAYLOADS ---

data class TagBankTransactionRequest(
    @SerializedName("transactionId") val transactionId: String,
    @SerializedName("voucherId") val voucherId: String? = null,
    @SerializedName("category") val category: String? = null,
    @SerializedName("notes") val notes: String? = null
)

data class RecordPaymentRequest(
    @SerializedName("amount") val amount: Double,
    @SerializedName("paymentMode") val paymentMode: String = "Bank Transfer",
    @SerializedName("paymentDate") val paymentDate: String? = null,
    @SerializedName("notes") val notes: String? = null
)
