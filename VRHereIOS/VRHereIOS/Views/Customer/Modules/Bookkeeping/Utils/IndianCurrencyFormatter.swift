import Foundation

public struct IndianCurrencyFormatter {

    public static func format(_ amount: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .currency
        formatter.currencySymbol = "₹"
        formatter.locale = Locale(identifier: "en_IN")
        formatter.minimumFractionDigits = 2
        formatter.maximumFractionDigits = 2
        return formatter.string(from: NSNumber(value: amount)) ?? "₹\(String(format: "%.2f", amount))"
    }

    public static func formatNoDecimals(_ amount: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .currency
        formatter.currencySymbol = "₹"
        formatter.locale = Locale(identifier: "en_IN")
        formatter.minimumFractionDigits = 0
        formatter.maximumFractionDigits = 0
        return formatter.string(from: NSNumber(value: amount)) ?? "₹\(Int(amount))"
    }

    public static func numberToWords(_ amount: Double) -> String {
        var num = Int64(amount)
        if num == 0 { return "Zero Rupees Only" }

        let units = [
            "", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
            "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen",
            "Seventeen", "Eighteen", "Nineteen"
        ]
        let tens = [
            "", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"
        ]

        func convertChunk(_ n: Int) -> String {
            if n == 0 { return "" }
            if n < 20 { return units[n] + " " }
            if n < 100 { return tens[n / 10] + " " + units[n % 10] + " " }
            return units[n / 100] + " Hundred " + convertChunk(n % 100)
        }

        var words = ""

        let crore = Int(num / 10_000_000)
        num %= 10_000_000
        if crore > 0 {
            words += convertChunk(crore) + "Crore "
        }

        let lakh = Int(num / 100_000)
        num %= 100_000
        if lakh > 0 {
            words += convertChunk(lakh) + "Lakh "
        }

        let thousand = Int(num / 1_000)
        num %= 1_000
        if thousand > 0 {
            words += convertChunk(thousand) + "Thousand "
        }

        let hundred = Int(num / 100)
        num %= 100
        if hundred > 0 {
            words += convertChunk(hundred) + "Hundred "
        }

        if num > 0 {
            words += convertChunk(Int(num))
        }

        return words.trimmingCharacters(in: .whitespacesAndNewlines) + " Rupees Only"
    }
}
