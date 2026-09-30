package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.TrendingUp
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BookkeepingKPICard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

fun LazyListScope.reportsScreen(
    transactions: List<TransactionDto>,
    selectedMonth: String
) {
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val salesTx = transactions.filter { it.transactionType == "Sales" }
    val purchaseTx = transactions.filter { it.transactionType == "Purchase" }
    val expenseTx = transactions.filter { it.transactionType == "Expense" }
    val otherIncomeTx = transactions.filter { it.transactionType == "Income" }

    val totalSalesRevenue = salesTx.sumOf { it.summary.totalTaxableValue }
    val totalOtherIncome = otherIncomeTx.sumOf { it.summary.totalTaxableValue }
    val totalIncome = totalSalesRevenue + totalOtherIncome

    val totalPurchasesCost = purchaseTx.sumOf { it.summary.totalTaxableValue }
    val totalOperationalExpenses = expenseTx.sumOf { it.summary.totalTaxableValue }
    val totalExpenses = totalPurchasesCost + totalOperationalExpenses

    val netProfit = totalIncome - totalExpenses
    val isProfitable = netProfit >= 0

    val outputGst = salesTx.sumOf { it.summary.totalCgst + it.summary.totalSgst + it.summary.totalIgst }
    val inputItc = purchaseTx.sumOf { it.summary.totalCgst + it.summary.totalSgst + it.summary.totalIgst }
    val netGstPayable = (outputGst - inputItc).coerceAtLeast(0.0)

    // 1. Profit & Loss Summary Card
    item {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = Color(0xFF0F172A),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("PROFIT & LOSS STATEMENT", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8), letterSpacing = 1.sp)
                        Text(selectedMonth, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                    Surface(
                        shape = RoundedCornerShape(20.dp),
                        color = if (isProfitable) Color(0xFFDCFCE7) else Color(0xFFFEE2E2)
                    ) {
                        Text(
                            text = if (isProfitable) "NET PROFIT" else "NET LOSS",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black,
                            color = if (isProfitable) Color(0xFF16A34A) else Color(0xFFDC2626),
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                        )
                    }
                }

                HorizontalDivider(color = Color.White.copy(alpha = 0.15f))

                // Breakdown Rows
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Total Revenue (Sales + Other Income)", fontSize = 12.sp, color = Color(0xFFCBD5E1))
                    Text(IndianCurrencyFormatter.format(totalIncome), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Total Cost & Expenses (Purchases + OpEx)", fontSize = 12.sp, color = Color(0xFFCBD5E1))
                    Text(IndianCurrencyFormatter.format(totalExpenses), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                }

                HorizontalDivider(color = Color.White.copy(alpha = 0.15f))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Estimated Net Margin", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color.White)
                    Text(
                        text = IndianCurrencyFormatter.format(netProfit),
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = if (isProfitable) Color(0xFF4ADE80) else Color(0xFFF87171)
                    )
                }
            }
        }
    }

    // 2. GST Tax Computation Sheet
    item {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = Color.White,
            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
            shadowElevation = 1.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text("GST Tax Liability Summary", fontSize = 14.sp, fontWeight = FontWeight.Black, color = textDark)

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Output Tax (GSTR-1 Sales)", fontSize = 12.sp, color = textMuted)
                    Text(IndianCurrencyFormatter.format(outputGst), fontSize = 12.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Input Tax Credit (GSTR-2B Purchases)", fontSize = 12.sp, color = textMuted)
                    Text("- " + IndianCurrencyFormatter.format(inputItc), fontSize = 12.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF059669))
                }

                HorizontalDivider(color = Color(0xFFF1F5F9))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Net Tax Payable in Cash", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)
                    Text(IndianCurrencyFormatter.format(netGstPayable), fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFFEF4444))
                }
            }
        }
    }
}
