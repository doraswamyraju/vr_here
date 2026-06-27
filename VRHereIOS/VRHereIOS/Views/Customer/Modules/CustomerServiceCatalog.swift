import SwiftUI

struct ServicePackage: Codable, Identifiable {
    let id: String
    let name: String
    let price: Double
    var isAdjustable: Bool = false
    var isPopular: Bool = false
    let description: String
    let features: [String]
    let creativeButtonText: String
}

struct ServiceDetail: Codable, Identifiable {
    let id: String
    let title: String
    let description: String
    let iconKey: String
    let packages: [ServicePackage]
}

class ServiceCatalog: ObservableObject {
    static let shared = ServiceCatalog()
    
    @Published var items: [String: ServiceDetail] = [
        "pvt-ltd-registration": ServiceDetail(
            id: "pvt-ltd-registration",
            title: "Private Limited Registration",
            description: "Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.",
            iconKey: "building",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Start here if you are unsure. Fee fully adjusted against registration.", features: ["30 Mins CA/CS Call", "Business Structure Advice", "Name Availability Check", "Compliance Roadmap"], creativeButtonText: "Consult CA/CS Now"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 5499.0, description: "Essential registration for verified startups.", features: ["Name Approval (RUN)", "COI, PAN & TAN", "MOA & AOA", "2 DIN & 2 DSC", "PF/ESI/MSME registration"], creativeButtonText: "Launch Basic Setup"),
                ServicePackage(id: "advance", name: "Advance Plan", price: 11399.0, isPopular: true, description: "Complete compliance & web presence.", features: ["Everything in Basic", "GST Registration", "Import Export Code (IEC)", "ISO Certification", "Professional Website"], creativeButtonText: "Unlock Premium Growth")
            ]
        ),
        "gst-registration": ServiceDetail(
            id: "gst-registration",
            title: "GST Registration",
            description: "Get your GST number quickly and start filing returns. Essential for businesses with turnover above thresholds.",
            iconKey: "file",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Speak with our tax expert about your GST eligibility and documents.", features: ["30 Mins Call", "Eligibility Check", "Documents List Review", "State-Specific Rules"], creativeButtonText: "Speak with Tax Expert"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 2569.0, description: "Essential GST registration package.", features: ["New GST Registration", "Updating Bank Account", "1st Month GST Return"], creativeButtonText: "Get Registered Now"),
                ServicePackage(id: "expert", name: "Expert Plan", price: 9059.0, isPopular: true, description: "Complete tax compliance suite.", features: ["Everything in Basic", "LUT Filing", "IEC Code Application", "2 Months GST Returns", "Priority Support"], creativeButtonText: "Go Pro Compliance")
            ]
        ),
        "partnership-firm": ServiceDetail(
            id: "partnership-firm",
            title: "Partnership Firm Registration",
            description: "Ideal for small businesses with multiple owners. Shared responsibilities and faster decision making.",
            iconKey: "people",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Discuss partnership clauses and legal requirements with our experts.", features: ["Partnership Deed Advice", "Clause Review", "Tax Implication Call"], creativeButtonText: "Draft Partners Deed"),
                ServicePackage(id: "basic", name: "Basic Plan", price: 4899.0, description: "Essential registration for partnership firms.", features: ["Deed Drafting", "PAN & TAN Applications", "Firm Registration", "Notary Assistance"], creativeButtonText: "Establish Partnership")
            ]
        ),
        "income-tax-return": ServiceDetail(
            id: "income-tax-return",
            title: "Income Tax Return (ITR)",
            description: "End-to-end ITR filing support for salaried, professionals, and businesses with compliance-first review.",
            iconKey: "calculator",
            packages: [
                ServicePackage(id: "consultation", name: "Expert Consultation", price: 499.0, isAdjustable: true, description: "Review your tax computation and self-assessment with a CA.", features: ["Tax Planning Call", "Computation Review", "Deduction Guidance"], creativeButtonText: "Solve Tax Doubts"),
                ServicePackage(id: "itr-filing", name: "ITR Filing", price: 1499.0, isPopular: true, description: "Standard filing service for individuals/professionals.", features: ["ITR 1 to 4 Support", "Computation Review", "Notice Response Guidance"], creativeButtonText: "Secure My Tax Filing")
            ]
        )
    ]
    
    private init() {}
    
    func updateFromApi(apiData: [MobileServiceDetail]) {
        for apiDetail in apiData {
            let pkgs = apiDetail.packages.map { apiPkg in
                ServicePackage(
                    id: apiPkg.id,
                    name: apiPkg.name,
                    price: apiPkg.price,
                    isAdjustable: apiPkg.isAdjustable,
                    isPopular: apiPkg.isPopular,
                    description: apiPkg.description,
                    features: apiPkg.features,
                    creativeButtonText: apiPkg.buttonText
                )
            }
            items[apiDetail.pageId] = ServiceDetail(
                id: apiDetail.pageId,
                title: apiDetail.title,
                description: apiDetail.description,
                iconKey: apiDetail.iconKey,
                packages: pkgs
            )
        }
    }
}

func getIconName(key: String) -> String {
    switch key.lowercased() {
    case "apartment", "building": return "building.2"
    case "description", "file": return "doc.text"
    case "people", "group": return "person.3"
    case "calculate", "calculator": return "calculator"
    case "star": return "star"
    case "phone": return "phone"
    default: return "briefcase"
    }
}

func getAbsoluteURL(path: String) -> URL? {
    let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { return nil }
    if trimmed.lowercased().hasPrefix("http://") || trimmed.lowercased().hasPrefix("https://") {
        return URL(string: trimmed)
    }
    let cleanPath = trimmed.hasPrefix("/") ? String(trimmed.dropFirst()) : trimmed
    return URL(string: "https://vrhere.in/\(cleanPath)")
}
