import SwiftUI

struct AdminCrmTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var activeCategoryTab = "ALL" // "ALL", "PACKAGE_CLICK", "PAGE_VIEW", "CONVERTED"
    @State private var statusFilter = "ALL" // "ALL", "NEW", "CONTACTED", "IN_PROGRESS", "CONVERTED", "LOST"
    @State private var expandedClients: Set<String> = []
    @State private var clientNoteInputs: [String: String] = [:]
    
    // Grouped Client Structure for 1:1 UI
    struct GroupedClient: Identifiable {
        let id: String
        let customerName: String
        let email: String
        let phone: String
        let isMember: Bool
        var status: String
        let highestCategory: String
        let totalPriceInterest: Double
        let sources: [String]
        let services: [ClientServiceIntent]
        let leadIds: [String]
        let notes: [LeadNote]
        let lastActivityAt: String
    }
    
    struct ClientServiceIntent: Identifiable {
        var id: String { serviceName }
        let serviceName: String
        let packageName: String?
        let price: Double
        let category: String
        let clickCount: Int
        let lastActivityAt: String
    }

    var groupedClients: [GroupedClient] {
        var map: [String: GroupedClient] = [:]
        
        for lead in viewModel.leads {
            let phone = (lead.phone ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let email = (lead.email ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let name = (lead.customerName ?? "Guest Prospect").trimmingCharacters(in: .whitespacesAndNewlines)
            
            let key: String
            if !phone.isEmpty && phone.count >= 7 {
                key = "phone_\(phone)"
            } else if !email.isEmpty && email.contains("@") {
                key = "email_\(email)"
            } else {
                key = "lead_\(lead.id)"
            }
            
            let svcIntent = ClientServiceIntent(
                serviceName: lead.serviceName ?? "General Inquiry",
                packageName: lead.packageName,
                price: lead.price ?? 0.0,
                category: lead.category ?? "PAGE_VIEW",
                clickCount: lead.category == "PACKAGE_CLICK" ? 1 : 0,
                lastActivityAt: lead.lastActivityAt ?? lead.createdAt ?? ""
            )
            
            if let existing = map[key] {
                var updatedServices = existing.services
                if !updatedServices.contains(where: { $0.serviceName == svcIntent.serviceName }) {
                    updatedServices.append(svcIntent)
                }
                var updatedNotes = existing.notes
                for n in lead.notes {
                    if !updatedNotes.contains(where: { $0.id == n.id }) {
                        updatedNotes.append(n)
                    }
                }
                var updatedLeadIds = existing.leadIds
                if !updatedLeadIds.contains(lead.id) {
                    updatedLeadIds.append(lead.id)
                }
                
                let isHot = existing.highestCategory == "PACKAGE_CLICK" || lead.category == "PACKAGE_CLICK"
                
                map[key] = GroupedClient(
                    id: existing.id,
                    customerName: existing.customerName == "Guest Prospect" && name != "Guest Prospect" ? name : existing.customerName,
                    email: existing.email.isEmpty ? email : existing.email,
                    phone: existing.phone.isEmpty ? phone : existing.phone,
                    isMember: existing.isMember,
                    status: existing.status,
                    highestCategory: isHot ? "PACKAGE_CLICK" : "PAGE_VIEW",
                    totalPriceInterest: existing.totalPriceInterest + (lead.price ?? 0.0),
                    sources: Array(Set(existing.sources + [lead.source ?? "web"])),
                    services: updatedServices,
                    leadIds: updatedLeadIds,
                    notes: updatedNotes,
                    lastActivityAt: lead.lastActivityAt ?? existing.lastActivityAt
                )
            } else {
                map[key] = GroupedClient(
                    id: key,
                    customerName: name,
                    email: email,
                    phone: phone,
                    isMember: !email.isEmpty,
                    status: lead.status ?? "NEW",
                    highestCategory: lead.category ?? "PAGE_VIEW",
                    totalPriceInterest: lead.price ?? 0.0,
                    sources: [lead.source ?? "web"],
                    services: [svcIntent],
                    leadIds: [lead.id],
                    notes: lead.notes,
                    lastActivityAt: lead.lastActivityAt ?? lead.createdAt ?? ""
                )
            }
        }
        
        return Array(map.values).sorted { $0.lastActivityAt > $1.lastActivityAt }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Banner
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 6) {
                                Circle().fill(Color.green).frame(width: 8, height: 8)
                                Text("LIVE INTENT TELEMETRY CRM")
                                    .font(.system(size: 9, weight: .black))
                                    .foregroundColor(.cyan)
                                    .tracking(1.5)
                            }
                            Text("Leads & Intent Engine")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        Button(action: {
                            if expandedClients.count == groupedClients.count {
                                expandedClients.removeAll()
                            } else {
                                expandedClients = Set(groupedClients.map { $0.id })
                            }
                        }) {
                            Text(expandedClients.count == groupedClients.count ? "Collapse All" : "Expand All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Color.white.opacity(0.15))
                                .cornerRadius(10)
                        }
                    }
                    
                    Text("All mobile and web interactions are aggregated by client profile. Review journey, package clicks, and unified notes.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 20/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Metrics Cards Bar
                metricsCardsBar
                
                // Search Bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search by client, service, phone, or email...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                .padding(.horizontal, 20)
                
                // Category Filter Chips
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        filterChip(title: "All Leads", key: "ALL", current: activeCategoryTab) { activeCategoryTab = "ALL" }
                        filterChip(title: "🔥 Hot Intent (Package Clicks)", key: "PACKAGE_CLICK", current: activeCategoryTab) { activeCategoryTab = "PACKAGE_CLICK" }
                        filterChip(title: "👀 Browsing Views", key: "PAGE_VIEW", current: activeCategoryTab) { activeCategoryTab = "PAGE_VIEW" }
                        filterChip(title: "✅ Converted", key: "CONVERTED", current: activeCategoryTab) { activeCategoryTab = "CONVERTED" }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Status Filter Chips
                let statuses = ["ALL", "NEW", "CONTACTED", "IN_PROGRESS", "CONVERTED", "LOST"]
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(statuses, id: \.self) { st in
                            filterChip(title: st, key: st, current: statusFilter) { statusFilter = st }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Filtered Clients List
                let filtered = groupedClients.filter { client in
                    let q = searchQuery.lowercased()
                    let matchesSearch = q.isEmpty ||
                        client.customerName.lowercased().contains(q) ||
                        client.email.lowercased().contains(q) ||
                        client.phone.lowercased().contains(q) ||
                        client.services.contains(where: { $0.serviceName.lowercased().contains(q) })
                    
                    let matchesCat: Bool
                    if activeCategoryTab == "ALL" {
                        matchesCat = true
                    } else if activeCategoryTab == "CONVERTED" {
                        matchesCat = client.status.uppercased() == "CONVERTED"
                    } else {
                        matchesCat = client.highestCategory == activeCategoryTab
                    }
                    
                    let matchesStatus: Bool
                    if statusFilter == "ALL" {
                        matchesStatus = true
                    } else {
                        matchesStatus = client.status.uppercased() == statusFilter
                    }
                    
                    return matchesSearch && matchesCat && matchesStatus
                }
                
                VStack(spacing: 14) {
                    if filtered.isEmpty {
                        VStack(spacing: 10) {
                            Image(systemName: "person.crop.circle.badge.questionmark")
                                .font(.system(size: 36))
                                .foregroundColor(.textMuted)
                            Text("No telemetry leads found")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 40)
                    } else {
                        ForEach(filtered) { client in
                            clientLeadCard(client: client)
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }

    // MARK: - Metrics Cards Bar
    private var metricsCardsBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                metricCard(
                    title: "UNIQUE CLIENTS",
                    value: "\(groupedClients.count)",
                    sub: "\(viewModel.leadStats?.total ?? viewModel.leads.count) Total Events",
                    icon: "person.3.fill",
                    color: .indigo
                )
                metricCard(
                    title: "HOT INTENT",
                    value: "\(viewModel.leadStats?.packageClicks ?? viewModel.leads.filter { $0.category == "PACKAGE_CLICK" }.count)",
                    sub: "Package Price Clicks",
                    icon: "flame.fill",
                    color: .red
                )
                metricCard(
                    title: "BROWSING VIEWS",
                    value: "\(viewModel.leadStats?.pageViews ?? viewModel.leads.filter { $0.category == "PAGE_VIEW" }.count)",
                    sub: "Service Page Views",
                    icon: "eye.fill",
                    color: .blue
                )
                metricCard(
                    title: "CONVERTED",
                    value: "\(viewModel.leadStats?.converted ?? viewModel.leads.filter { $0.status == "CONVERTED" }.count)",
                    sub: "\(viewModel.leadStats?.conversionRate ?? "0.0")% Win Rate",
                    icon: "checkmark.seal.fill",
                    color: .green
                )
            }
            .padding(.horizontal, 20)
        }
    }

    private func metricCard(title: String, value: String, sub: String, icon: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(.system(size: 9, weight: .black))
                    .foregroundColor(color)
                    .tracking(1)
                Spacer()
                Image(systemName: icon)
                    .font(.system(size: 13))
                    .foregroundColor(color)
            }
            Text(value)
                .font(.system(size: 22, weight: .black))
                .foregroundColor(.textDark)
            Text(sub)
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(.textMuted)
        }
        .padding(14)
        .frame(width: 155)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(color.opacity(0.2), lineWidth: 1))
        .shadow(color: color.opacity(0.04), radius: 6, y: 3)
    }

    // MARK: - Client Lead Card
    private func clientLeadCard(client: GroupedClient) -> some View {
        let isExpanded = expandedClients.contains(client.id)
        
        return VStack(alignment: .leading, spacing: 14) {
            // Card Top Bar
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(client.customerName)
                            .font(.system(size: 14, weight: .black))
                            .foregroundColor(.textDark)
                        if client.isMember {
                            Text("MEMBER")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.indigo)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.indigo.opacity(0.12))
                                .cornerRadius(4)
                        }
                    }
                    
                    HStack(spacing: 12) {
                        if !client.phone.isEmpty {
                            Text(client.phone)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.textMuted)
                        }
                        if !client.email.isEmpty {
                            Text(client.email)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.textMuted)
                        }
                    }
                }
                
                Spacer()
                
                // Status Badge
                Menu {
                    let statuses = ["NEW", "CONTACTED", "IN_PROGRESS", "CONVERTED", "LOST"]
                    ForEach(statuses, id: \.self) { st in
                        Button(st) {
                            if let firstLeadId = client.leadIds.first {
                                viewModel.updateLeadStatus(leadId: firstLeadId, status: st)
                            }
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Text(client.status.uppercased())
                            .font(.system(size: 9, weight: .black))
                        Image(systemName: "chevron.down")
                            .font(.system(size: 8, weight: .bold))
                    }
                    .foregroundColor(leadStatusColor(client.status))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(leadStatusColor(client.status).opacity(0.12))
                    .cornerRadius(8)
                }
            }
            
            // Intent & Price Badge Row
            HStack {
                if client.highestCategory == "PACKAGE_CLICK" {
                    HStack(spacing: 4) {
                        Image(systemName: "flame.fill")
                        Text("HOT INTENT")
                    }
                    .font(.system(size: 9, weight: .black))
                    .foregroundColor(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.red)
                    .cornerRadius(6)
                } else {
                    HStack(spacing: 4) {
                        Image(systemName: "eye.fill")
                        Text("BROWSING")
                    }
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(.blue)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.blue.opacity(0.12))
                    .cornerRadius(6)
                }
                
                if client.totalPriceInterest > 0 {
                    Text("Interest: ₹\(Int(client.totalPriceInterest))")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.green)
                }
                
                Spacer()
                
                // Expand / Collapse Accordion Button
                Button(action: {
                    if isExpanded {
                        expandedClients.remove(client.id)
                    } else {
                        expandedClients.insert(client.id)
                    }
                }) {
                    HStack(spacing: 4) {
                        Text("\(client.services.count) Services")
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    }
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.indigo)
                }
            }
            
            // Direct Contact Action Buttons
            HStack(spacing: 8) {
                if !client.phone.isEmpty {
                    Button(action: {
                        let clean = client.phone.replacingOccurrences(of: "+", with: "").replacingOccurrences(of: " ", with: "")
                        let formatted = clean.count == 10 ? "91\(clean)" : clean
                        let topSvc = client.services.first?.serviceName ?? "VR Here Services"
                        let msg = "Hi \(client.customerName), I noticed you were exploring *\(topSvc)* on VR Here. How can our CA & legal experts assist you today?"
                        let encoded = msg.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
                        if let url = URL(string: "https://wa.me/\(formatted)?text=\(encoded)") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "message.fill")
                            Text("WhatsApp Quote")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.vertical, 7)
                        .frame(maxWidth: .infinity)
                        .background(Color.green)
                        .cornerRadius(8)
                    }
                    
                    Button(action: {
                        if let url = URL(string: "tel://\(client.phone)") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "phone.fill")
                            Text("Call")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.vertical, 7)
                        .frame(maxWidth: .infinity)
                        .background(Color.blue)
                        .cornerRadius(8)
                    }
                }
                
                // Assign Employee Menu
                Menu {
                    ForEach(viewModel.employees) { emp in
                        Button(emp.name) {
                            if let firstLeadId = client.leadIds.first {
                                viewModel.assignLead(leadId: firstLeadId, employeeId: emp.idVal)
                            }
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "person.crop.circle.badge.plus")
                        Text("Assign Staff")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textDark)
                    .padding(.vertical, 7)
                    .frame(maxWidth: .infinity)
                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                    .cornerRadius(8)
                }
            }
            
            // Expanded Journey & Services Accordion
            if isExpanded {
                Divider().background(Color.borderLight)
                
                VStack(alignment: .leading, spacing: 10) {
                    Text("EXPLORED SERVICES & PRICING")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(.textMuted)
                    
                    ForEach(client.services) { svc in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(svc.serviceName)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                if let pkg = svc.packageName {
                                    Text("Package: \(pkg)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                            }
                            Spacer()
                            if svc.price > 0 {
                                Text("₹\(Int(svc.price))")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.green)
                            }
                        }
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(10)
                    }
                    
                    // Unified Notes Section
                    Text("FOLLOW-UP NOTES")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(.textMuted)
                        .padding(.top, 4)
                    
                    // Preset Note Chips
                    let presetChips = ["📞 Called - No Answer", "💬 Sent WhatsApp Quote", "🤝 Follow up Tomorrow", "📋 Requested KYC Docs", "✅ Ready to Order"]
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(presetChips, id: \.self) { chip in
                                Button(action: {
                                    if let firstLeadId = client.leadIds.first {
                                        viewModel.addLeadNote(leadId: firstLeadId, text: chip)
                                    }
                                }) {
                                    Text(chip)
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(.textDark)
                                        .background(Color.white)
                                        .cornerRadius(6)
                                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.borderLight, lineWidth: 1))
                                }
                            }
                        }
                    }
                    
                    // Custom Note Field
                    HStack {
                        let noteBinding = Binding<String>(
                            get: { clientNoteInputs[client.id] ?? "" },
                            set: { clientNoteInputs[client.id] = $0 }
                        )
                        TextField("Log custom followup note...", text: noteBinding)
                            .font(.system(size: 12))
                            .padding(8)
                            .background(Color.white)
                            .cornerRadius(8)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderLight, lineWidth: 1))
                        
                        Button(action: {
                            if let text = clientNoteInputs[client.id], !text.isEmpty, let firstLeadId = client.leadIds.first {
                                viewModel.addLeadNote(leadId: firstLeadId, text: text) { _ in
                                    clientNoteInputs[client.id] = ""
                                }
                            }
                        }) {
                            Image(systemName: "paperplane.fill")
                                .font(.system(size: 12))
                                .foregroundColor(.white)
                                .padding(8)
                                .background(Color.indigo)
                                .cornerRadius(8)
                        }
                    }
                    
                    // Notes History
                    if !client.notes.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(client.notes) { n in
                                HStack(alignment: .top, spacing: 6) {
                                    Image(systemName: "bubble.left.fill")
                                        .font(.system(size: 10))
                                        .foregroundColor(.indigo)
                                        .padding(.top, 2)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(n.text)
                                            .font(.system(size: 11, weight: .medium))
                                            .foregroundColor(.textDark)
                                        if let dt = n.createdAt {
                                            Text(dt)
                                                .font(.system(size: 9))
                                                .foregroundColor(.textMuted)
                                        }
                                    }
                                }
                                .padding(8)
                                .background(Color.white)
                                .cornerRadius(8)
                            }
                        }
                    }
                }
            }
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(18)
        .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
    }

    private func filterChip(title: String, key: String, current: String, action: @escaping () -> Void) -> some View {
        let isSelected = key == current
        return Button(action: action) {
            Text(title)
                .font(.system(size: 11, weight: .bold))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                .background(isSelected ? Color.indigo : Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(isSelected ? Color.indigo : Color.borderLight, lineWidth: 1))
        }
    }

    private func leadStatusColor(_ status: String) -> Color {
        switch status.uppercased() {
        case "CONVERTED", "WON":
            return .green
        case "CONTACTED", "IN_PROGRESS":
            return .blue
        case "NEW":
            return .orange
        case "LOST":
            return .red
        default:
            return .gray
        }
    }
}
