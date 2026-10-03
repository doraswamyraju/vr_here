import SwiftUI

public struct PartiesScreen: View {
    public let parties: [PartyDto]
    @Binding public var selectedTypeFilter: String // "All", "Customer", "Vendor"
    @Binding public var searchQuery: String
    public let onAddParty: () -> Void
    public let onEditParty: (PartyDto) -> Void
    public let onDeleteParty: (PartyDto) -> Void

    private var customersCount: Int {
        parties.count { $0.partyType.caseInsensitiveCompare("Customer") == .orderedSame || $0.partyType.caseInsensitiveCompare("Both") == .orderedSame }
    }

    private var vendorsCount: Int {
        parties.count { $0.partyType.caseInsensitiveCompare("Vendor") == .orderedSame || $0.partyType.caseInsensitiveCompare("Both") == .orderedSame }
    }

    private var filtered: [PartyDto] {
        parties.filter { p in
            let typeMatch = selectedTypeFilter.caseInsensitiveCompare("All") == .orderedSame ||
                p.partyType.caseInsensitiveCompare(selectedTypeFilter) == .orderedSame ||
                p.partyType.caseInsensitiveCompare("Both") == .orderedSame
            let searchMatch = searchQuery.trimmingCharacters(in: .whitespaces).isEmpty ||
                p.name.localizedCaseInsensitiveContains(searchQuery) ||
                (p.tradeName?.localizedCaseInsensitiveContains(searchQuery) ?? false) ||
                (p.gstin?.localizedCaseInsensitiveContains(searchQuery) ?? false) ||
                (p.phone?.localizedCaseInsensitiveContains(searchQuery) ?? false)
            return typeMatch && searchMatch
        }
    }

    public var body: some View {
        VStack(spacing: 14) {
            // 1. KPI Summaries
            HStack(spacing: 10) {
                BookkeepingKPICard(
                    title: "Total Customers",
                    value: "\(customersCount) Parties",
                    subtitle: "Active Clients & Buyers",
                    icon: "person.fill",
                    accentColor: Color(red: 79/255, green: 70/255, blue: 229/255)
                )

                BookkeepingKPICard(
                    title: "Total Vendors",
                    value: "\(vendorsCount) Vendors",
                    subtitle: "Suppliers & Contractors",
                    icon: "building.2.fill",
                    accentColor: Color(red: 5/255, green: 150/255, blue: 105/255)
                )
            }

            // 2. Search & Add Party Bar
            HStack(spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .font(.system(size: 14))
                    TextField("Search party / GSTIN...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(.horizontal, 12)
                .frame(height: 44)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )

                Button(action: onAddParty) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 12, weight: .bold))
                        Text("Add Party")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .frame(height: 44)
                    .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                    .cornerRadius(12)
                }
            }

            // 3. Type Filters Bar
            HStack(spacing: 6) {
                ForEach(["All", "Customer", "Vendor"], id: \.self) { t in
                    let isSel = selectedTypeFilter.caseInsensitiveCompare(t) == .orderedSame
                    Button(action: { selectedTypeFilter = t }) {
                        Text(t)
                            .font(.system(size: 11, weight: isSel ? .black : .bold))
                            .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(isSel ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color.white)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(isSel ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                    }
                }
                Spacer()
            }

            // 4. Parties List
            if filtered.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "person.2")
                        .font(.system(size: 30))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("No Parties Registered")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Text("Add your customers and suppliers to auto-fill invoices.")
                        .font(.system(size: 11))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                .frame(maxWidth: .infinity)
                .padding(28)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
            } else {
                VStack(spacing: 10) {
                    ForEach(filtered) { p in
                        PartyItemCard(
                            party: p,
                            onEdit: { onEditParty(p) },
                            onDelete: { onDeleteParty(p) }
                        )
                    }
                }
            }
        }
    }
}
