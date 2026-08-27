package com.sbr.vrherebms.ui.screens.customer

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

data class ServiceCategory(
    val id: String,
    val title: String,
    val icon: ImageVector,
    val columns: List<ServiceColumn>
)

data class ServiceColumn(
    val title: String,
    val items: List<String>
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerServicesTab(
    viewModel: CustomerDashboardViewModel,
    onSelectTab: (String) -> Unit,
    onOpenLiveService: (String, String) -> Unit
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }

    val liveServicesMap = remember {
        mapOf(
            // Corporate Entities
            "Private Limited Company" to "https://vrhere.in/pvt-ltd-registration",
            "Public Limited Company" to "https://vrhere.in/public-limited-company",
            "LLP Registration" to "https://vrhere.in/llp-registration",
            "Limited Liability Partnership (LLP)" to "https://vrhere.in/llp-registration",
            "Partnership Firm Registration" to "https://vrhere.in/partnership-firm",
            "Proprietorship Setup" to "https://vrhere.in/proprietorship-setup",
            "Section 8 Company (NGO)" to "https://vrhere.in/section-8-company",
            "One Person Company" to "https://vrhere.in/one-person-company",
            "Society / Trust Registration" to "https://vrhere.in/society-trust-registration",
            
            // Tax & Accounting
            "Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)" to "https://vrhere.in/cloud-accounting",
            "GST Return Filing" to "https://vrhere.in/gst-return-filing",
            "Payroll Management (Payslips, Leave, Form 16)" to "https://vrhere.in/payroll-management",
            "Professional Tax (PT) Returns" to "https://vrhere.in/professional-tax",
            "EPF / ESI Returns" to "https://vrhere.in/epf-esi-returns",
            "TDS/TCS Filing" to "https://vrhere.in/tds-tcs-filing",
            "Monthly MIS Reports" to "https://vrhere.in/mis-reporting",
            "Internal Audit" to "https://vrhere.in/audit-services",
            "GST Audit" to "https://vrhere.in/audit-services",
            "GST Registration" to "https://vrhere.in/gst-registration",
            "Income Tax Return Filing (ITR 1-7)" to "https://vrhere.in/income-tax-return",
            "12AA/80G Certificates" to "https://vrhere.in/12aa-80g-certificates",
            "Companies Compliance Scheme 2026 (CCFS)" to "https://vrhere.in/compliance-scheme-2026",

            // ISO & Quality
            "ISO 9001:2015 - Quality Management" to "https://vrhere.in/iso-9001-certification",
            "ISO 14001:2015 - Environmental Management" to "https://vrhere.in/iso-14001-certification",
            "ISO 45001:2018 - Occupational Health & Safety" to "https://vrhere.in/iso-45001-certification",
            "ISO 22000:2018 - Food Safety" to "https://vrhere.in/iso-22000-certification",
            "ISO 27001:2022 - Information Security" to "https://vrhere.in/iso-27001-certification",
            "GMP / HACCP" to "https://vrhere.in/gmp-haccp-certification",
            "CE Marking" to "https://vrhere.in/ce-marking-certification",
            "ISI / BIS Certification" to "https://vrhere.in/isi-bis-certification",
            "Halal Certification" to "https://vrhere.in/halal-kosher-certification",
            "Kosher Certification" to "https://vrhere.in/halal-kosher-certification",

            // Licensing & Government
            "Udyam Registration (MSME)" to "https://vrhere.in/udyam-registration",
            "Shops & Establishment Registration" to "https://vrhere.in/shops-establishment-license",
            "Import Export Code (IEC)" to "https://vrhere.in/import-export-code",
            "Startup India Registration" to "https://vrhere.in/startup-india-registration",
            "FSSAI Registration / License" to "https://vrhere.in/fssai-license",
            "Trade License" to "https://vrhere.in/trade-license",
            "Labour / Contract Labour License" to "https://vrhere.in/labour-license",
            "Pollution Control Board NOC / CFE / CFO" to "https://vrhere.in/pollution-noc",
            "ROC Annual Filings (AOC-4, MGT-7)" to "https://vrhere.in/roc-annual-filings",
            "Director KYC (DIR-3 KYC)" to "https://vrhere.in/director-kyc",
            "Digital Signatures (DSC Class 3)" to "https://vrhere.in/dsc-registration",

            // MSME & Schemes
            "GeM Seller Registration" to "https://vrhere.in/gem-registration",
            "TReDS Registration" to "https://vrhere.in/treds-registration",
            "RERA Registration" to "https://vrhere.in/rera-registration",
            "DPR Preparation" to "https://vrhere.in/dpr-cma-preparation",
            "CMA Data Preparation" to "https://vrhere.in/dpr-cma-preparation",
            "PMEGP Loan Support" to "https://vrhere.in/msme-subsidies-loans",
            "CGTMSE Loan Support" to "https://vrhere.in/msme-subsidies-loans",
            "Mudra Loans" to "https://vrhere.in/msme-subsidies-loans",

            // Branding & Setup
            "Trademark Registration" to "https://vrhere.in/trademark-registration",
            "Machinery Sourcing" to "https://vrhere.in/machinery-sourcing"
        )
    }

    val categories = remember {
        listOf(
            ServiceCategory(
                id = "accounting-compliance-taxation",
                title = "Accounting, Compliance & Taxation Services",
                icon = Icons.Default.Calculate,
                columns = listOf(
                    ServiceColumn(
                        title = "Accounting-as-a-Service (AaaS)",
                        items = listOf(
                            "Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)",
                            "GST Return Filing",
                            "Payroll Management (Payslips, Leave, Form 16)",
                            "Professional Tax (PT) Returns",
                            "EPF / ESI Returns",
                            "Gratuity Management",
                            "TDS/TCS Filing",
                            "Inventory & Stock Management",
                            "Invoice Generation Support",
                            "Expense Tracking Consultancy",
                            "Monthly MIS Reports"
                        )
                    ),
                    ServiceColumn(
                        title = "Taxation & Legal Compliance",
                        items = listOf(
                            "Companies Compliance Scheme 2026 (CCFS)",
                            "GST Registration",
                            "Income Tax Return Filing (ITR 1-7)",
                            "12AA/80G Certificates",
                            "Tax Planning Support",
                            "15CA Certification"
                        )
                    ),
                    ServiceColumn(
                        title = "Audit Services",
                        items = listOf(
                            "Internal Audit",
                            "GST Audit",
                            "SOX Audit",
                            "Stock & Compliance Audit",
                            "Other Audits (Need Basis)"
                        )
                    )
                )
            ),
            ServiceCategory(
                id = "certification-quality-management",
                title = "Certification & Quality Management Services",
                icon = Icons.Default.Verified,
                columns = listOf(
                    ServiceColumn(
                        title = "ISO Services",
                        items = listOf(
                            "ISO 9001:2015 - Quality Management",
                            "ISO 14001:2015 - Environmental Management",
                            "ISO 45001:2018 - Occupational Health & Safety",
                            "ISO 22000:2018 - Food Safety",
                            "ISO 27001:2022 - Information Security",
                            "ISO 50001:2018 - Energy Management",
                            "ISO 13485:2016 - Medical Devices",
                            "ISO 20000-1:2018 - IT Service Management",
                            "ISO 22301:2019 - Business Continuity"
                        )
                    ),
                    ServiceColumn(
                        title = "Quality & Compliance",
                        items = listOf(
                            "GMP / HACCP",
                            "CE Marking",
                            "ISI / BIS Certification",
                            "FDA Compliance Support"
                        )
                    ),
                    ServiceColumn(
                        title = "Product & System Certifications",
                        items = listOf(
                            "BRCGS",
                            "Kosher Certification",
                            "Halal Certification"
                        )
                    )
                )
            ),
            ServiceCategory(
                id = "business-registration-licensing-corporate",
                title = "Business Registrations, Licensing & Corporate Services",
                icon = Icons.Default.BusinessCenter,
                columns = listOf(
                    ServiceColumn(
                        title = "Company / Business Entity Registrations",
                        items = listOf(
                            "Private Limited Company",
                            "Public Limited Company",
                            "LLP Registration",
                            "Partnership Firm Registration",
                            "Proprietorship Setup",
                            "Section 8 Company (NGO)",
                            "One Person Company",
                            "Society / Trust Registration"
                        )
                    ),
                    ServiceColumn(
                        title = "Mandatory Registrations",
                        items = listOf(
                            "Udyam Registration (MSME)",
                            "Shops & Establishment Registration",
                            "EPFO (PF) Registration",
                            "ESIC Registration",
                            "Professional Tax Registration",
                            "Startup India Registration",
                            "Import Export Code (IEC)"
                        )
                    ),
                    ServiceColumn(
                        title = "Licensing Services",
                        items = listOf(
                            "FSSAI Registration / License",
                            "LEI Certificate",
                            "Trade License",
                            "Labour / Contract Labour License",
                            "Pollution Control Board NOC / CFE / CFO",
                            "Factory License",
                            "FCRA",
                            "DARPAN for NGO"
                        )
                    ),
                    ServiceColumn(
                        title = "Corporate Compliances",
                        items = listOf(
                            "ROC Annual Filings (AOC-4, MGT-7)",
                            "Companies Compliance Scheme 2026 (CCFS)",
                            "Director KYC (DIR-3 KYC)",
                            "ROC Search Certificate",
                            "Charge Creation",
                            "Change in Shareholding",
                            "Change in Directorship",
                            "Merger / Demerger / Winding Up Compliance",
                            "Bonus / Loans / Buyback Compliance",
                            "Share Allotment & Transfer",
                            "Increase in Share Capital",
                            "Change in Name, Address, Objective",
                            "Digital Signatures (DSC Class 3)"
                        )
                    )
                )
            ),
            ServiceCategory(
                id = "government-msme-services",
                title = "Government & MSME Services",
                icon = Icons.Default.Public,
                columns = listOf(
                    ServiceColumn(
                        title = "GeM (Govt e-Marketplace)",
                        items = listOf(
                            "GeM Seller Registration",
                            "OEM Panel Registration",
                            "Brand Approval",
                            "Product Listing",
                            "Bid Participation & Tender Management"
                        )
                    ),
                    ServiceColumn(
                        title = "Other Portal Registrations",
                        items = listOf(
                            "TReDS Registration",
                            "RERA Registration",
                            "AP/TS Single Window",
                            "NPCI Registrations",
                            "Amazon/Flipkart Seller Registration Support"
                        )
                    ),
                    ServiceColumn(
                        title = "Project & Finance Support",
                        items = listOf(
                            "DPR Preparation",
                            "CMA Data Preparation",
                            "Bank Loans - Term Loan + Working Capital",
                            "CGTMSE Loan Support",
                            "PMEGP Loan Support",
                            "Mudra Loans",
                            "Stand-Up India Loan Assistance"
                        )
                    ),
                    ServiceColumn(
                        title = "MSME & Subsidy Schemes",
                        items = listOf(
                            "CLCSS / ZED Scheme Support",
                            "PMFME (Food Processing Units)",
                            "NSIC Schemes",
                            "NABARD Schemes",
                            "Cold Chain & Food Processing Subsidy",
                            "AP/TS State Industrial Subsidy Schemes"
                        )
                    )
                )
            ),
            ServiceCategory(
                id = "branding-industrial-setup",
                title = "Branding & Industrial Setup",
                icon = Icons.Default.Lightbulb,
                columns = listOf(
                    ServiceColumn(
                        title = "Startup & Branding Support",
                        items = listOf(
                            "Business Plan Preparation",
                            "Pitch Decks for Funding",
                            "Website & Branding Consulting",
                            "Vendor Empanelment Documentation",
                            "HR Policy Documentation",
                            "SOP Creation"
                        )
                    ),
                    ServiceColumn(
                        title = "Additional Services",
                        items = listOf(
                            "Loan File Documentation & Follow-up",
                            "Insurance Services (Business, Fire, Marine)",
                            "Digital Marketing Support",
                            "PAN / TAN Applications",
                            "Trademark & IP Services",
                            "Wealth Portfolio Management"
                        )
                    ),
                    ServiceColumn(
                        title = "Industrial Support",
                        items = listOf(
                            "Machinery Sourcing & Imports",
                            "Vendor Identification & Supplier Verification",
                            "Turnkey Machinery Setup Assistance",
                            "Technology Upgradation Consulting",
                            "Industry Selection & Feasibility Analysis"
                        )
                    )
                )
            )
        )
    }

    val filteredCategories = remember(searchQuery) {
        if (searchQuery.isBlank()) {
            categories
        } else {
            val q = searchQuery.lowercase().trim()
            categories.mapNotNull { category ->
                val filteredColumns = category.columns.mapNotNull { column ->
                    val filteredItems = column.items.filter { item ->
                        item.lowercase().contains(q) ||
                        column.title.lowercase().contains(q) ||
                        category.title.lowercase().contains(q)
                    }
                    if (filteredItems.isNotEmpty()) {
                        column.copy(items = filteredItems)
                    } else {
                        null
                    }
                }
                if (filteredColumns.isNotEmpty()) {
                    category.copy(columns = filteredColumns)
                } else {
                    null
                }
            }
        }
    }

    val totalResults = remember(filteredCategories) {
        filteredCategories.sumOf { cat -> cat.columns.sumOf { col -> col.items.size } }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        item {
            Column(modifier = Modifier.padding(bottom = 4.dp)) {
                Text(
                    "Services Catalog",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    "Select a specialized service to initiate your business journey.",
                    fontSize = 13.sp,
                    color = Color(0xFF64748B),
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }

        // Search Bar
        item {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search for legal, tax or industrial services...", fontSize = 13.sp, color = Color(0xFF94A3B8)) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = Color(0xFF64748B)) },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { searchQuery = "" }) {
                            Icon(Icons.Default.Close, contentDescription = "Clear", tint = Color(0xFF94A3B8))
                        }
                    }
                },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF6366F1),
                    unfocusedBorderColor = Color(0xFFE2E8F0),
                    focusedContainerColor = Color.White,
                    unfocusedContainerColor = Color.White
                ),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            )
        }

        // Search Results Indicator
        if (searchQuery.isNotBlank()) {
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        "$totalResults RESULT${if (totalResults != 1) "S" else ""} FOR",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF64748B),
                        letterSpacing = 0.5.sp
                    )
                    Box(
                        modifier = Modifier
                            .background(Color(0xFFEEF2F6), RoundedCornerShape(8.dp))
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(
                            "\"$searchQuery\"",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF6366F1)
                        )
                    }
                }
            }
        }

        // Categories List
        if (filteredCategories.isNotEmpty()) {
            items(filteredCategories, key = { it.id }) { category ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(28.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                ) {
                    Column(modifier = Modifier.padding(24.dp)) {
                        // Category Header
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(bottom = 20.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(48.dp)
                                    .background(Color(0xFFEEF2F6), RoundedCornerShape(14.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = category.icon,
                                    contentDescription = null,
                                    tint = Color(0xFF6366F1),
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(14.dp))
                            Text(
                                text = category.title,
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF1E293B),
                                lineHeight = 22.sp
                            )
                        }

                        // Column Lists
                        category.columns.forEachIndexed { colIdx, column ->
                            if (colIdx > 0) {
                                Spacer(modifier = Modifier.height(18.dp))
                            }
                            Column {
                                // Column Title
                                Text(
                                    text = column.title.uppercase(),
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8),
                                    letterSpacing = 1.sp,
                                    modifier = Modifier.padding(bottom = 6.dp)
                                )
                                HorizontalDivider(
                                    thickness = 1.dp,
                                    color = Color(0xFFF1F5F9)
                                )
                                Spacer(modifier = Modifier.height(6.dp))

                                // Items
                                column.items.forEach { item ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .scaleOnPress()
                                            .clickable {
                                                val liveUrl = liveServicesMap[item]
                                                if (liveUrl != null) {
                                                    onOpenLiveService(item, liveUrl)
                                                } else {
                                                    Toast.makeText(context, "Initiating inquiry for: $item", Toast.LENGTH_SHORT).show()
                                                    onSelectTab("Support")
                                                }
                                            }
                                            .padding(vertical = 10.dp, horizontal = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = item,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF475569),
                                            modifier = Modifier.weight(1f)
                                        )
                                        Icon(
                                            imageVector = Icons.Default.ChevronRight,
                                            contentDescription = null,
                                            tint = Color(0xFF94A3B8),
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Empty Results View
            item {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp),
                    shape = RoundedCornerShape(28.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp, horizontal = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.SearchOff,
                            contentDescription = null,
                            tint = Color(0xFF94A3B8),
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "No services found",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF475569)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "We couldn't find any match for \"$searchQuery\".\nTry different terms or request a custom setup.",
                            fontSize = 12.sp,
                            color = Color(0xFF94A3B8),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                            lineHeight = 16.sp
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Button(
                            onClick = { onSelectTab("Support") },
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
                        ) {
                            Text("Consult Support Expert", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        // Custom Request Card (shown only when no active search query)
        if (searchQuery.isBlank()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    shape = RoundedCornerShape(28.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
                ) {
                    Column(modifier = Modifier.padding(24.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .background(Color.White.copy(alpha = 0.1f), RoundedCornerShape(12.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Lightbulb,
                                    contentDescription = null,
                                    tint = Color(0xFFFBBF24)
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Text(
                                text = "Need a custom business solution?",
                                color = Color.White,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Black
                            )
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Our multidisciplinary experts can create tailored end-to-end setups, feasibility reports, and turnkey projects specifically for your industry.",
                            color = Color(0xFF94A3B8),
                            fontSize = 12.sp,
                            lineHeight = 16.sp
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Button(
                            onClick = { onSelectTab("Support") },
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                            modifier = Modifier
                                .fillMaxWidth()
                                .scaleOnPress()
                        ) {
                            Text("Consult Support Expert", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}
