package com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils

import java.text.DecimalFormat
import java.util.Locale

object IndianCurrencyFormatter {

    fun format(amount: Double): String {
        val formatter = DecimalFormat("##,##,##0.00")
        return "₹" + formatter.format(amount)
    }

    fun formatNoDecimals(amount: Double): String {
        val formatter = DecimalFormat("##,##,##0")
        return "₹" + formatter.format(amount)
    }

    fun numberToWords(amount: Double): String {
        val total = amount.toLong()
        if (total == 0L) return "Zero Rupees Only"

        val units = arrayOf(
            "", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
            "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen",
            "Seventeen", "Eighteen", "Nineteen"
        )
        val tens = arrayOf(
            "", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"
        )

        fun convertChunk(n: Int): String {
            if (n == 0) return ""
            if (n < 20) return units[n] + " "
            if (n < 100) return tens[n / 10] + " " + units[n % 10] + " "
            return units[n / 100] + " Hundred " + convertChunk(n % 100)
        }

        var num = total
        var words = ""

        val crore = (num / 10000000).toInt()
        num %= 10000000
        if (crore > 0) {
            words += convertChunk(crore) + "Crore "
        }

        val lakh = (num / 100000).toInt()
        num %= 100000
        if (lakh > 0) {
            words += convertChunk(lakh) + "Lakh "
        }

        val thousand = (num / 1000).toInt()
        num %= 1000
        if (thousand > 0) {
            words += convertChunk(thousand) + "Thousand "
        }

        val hundred = (num / 100).toInt()
        num %= 100
        if (hundred > 0) {
            words += convertChunk(hundred) + "Hundred "
        }

        if (num > 0) {
            words += convertChunk(num.toInt())
        }

        return words.trim() + " Rupees Only"
    }
}
