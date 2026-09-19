package com.sbr.vrherebms.ui.screens.customer.bookkeeping.models

data class MobileTransaction(
    val id: String,
    val type: String, // Sales, Purchase, Expense
    val docNumber: String,
    val date: String,
    val month: String, // e.g. "Sep 2026"
    val partyName: String,
    val gstin: String,
    val amount: Double,
    val taxAmount: Double,
    val paymentMode: String = "Bank Transfer",
    val status: String // Paid, Pending
)

data class MobileParty(
    val id: String,
    val name: String,
    val type: String, // Customer, Vendor
    val gstin: String,
    val pan: String = "",
    val phone: String,
    val address: String = "Tirupati, Andhra Pradesh",
    val balance: Double
)

data class MobileStaffPayroll(
    val id: String,
    val name: String,
    val role: String,
    val basic: Double,
    val hra: Double,
    val allowance: Double,
    val deductions: Double,
    val netSalary: Double,
    val status: String
)

data class MobileBankStatement(
    val id: String,
    val bankName: String,
    val accountNumber: String,
    val balance: Double,
    val unreconciledCount: Int,
    val lastSync: String
)
