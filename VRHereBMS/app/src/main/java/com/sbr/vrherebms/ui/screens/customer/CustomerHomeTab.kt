package com.sbr.vrherebms.ui.screens.customer

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.components.scaleOnPress
import com.sbr.vrherebms.ui.theme.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
private fun StatusBadge(status: String) {
    val (bgColor, textColor, borderColor) = when (status) {
        "Processing at Portal", "In Progress" -> Triple(Color(0xFFEFF6FF), Color(0xFF1D4ED8), Color(0xFFBFDBFE))
        "Waiting for Clarification", "In Review" -> Triple(Color(0xFFFAF5FF), Color(0xFF7E22CE), Color(0xFFE9D5FF))
        "Completed", "Approved" -> Triple(Color(0xFFECFDF5), Color(0xFF047857), Color(0xFFA7F3D0))
        "Pending Documents", "Documents Required" -> Triple(Color(0xFFFFFBEB), Color(0xFFB45309), Color(0xFFFDE68A))
        "Documents Verified" -> Triple(Color(0xFFECFDF5), Color(0xFF059669), Color(0xFFA7F3D0))
        else -> Triple(Color(0xFFF1F5F9), Color(0xFF334155), Color(0xFFE2E8F0))
    }

    Surface(
        color = bgColor,
        border = BorderStroke(1.dp, borderColor),
        shape = RoundedCornerShape(20.dp)
    ) {
        Text(
            text = status.uppercase(),
            fontSize = 9.sp,
            fontWeight = FontWeight.Black,
            color = textColor,
            letterSpacing = 0.5.sp,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        )
    }
}

private data class QuickServiceItem(
    val id: Int,
    val name: String,
    val tag: String,
    val icon: ImageVector,
    val iconBg: Color,
    val iconTint: Color,
    val key: String,
    val url: String? = null
)

private data class PromoOfferItem(
    val id: String,
    val tag: String,
    val title: String,
    val description: String,
    val badge: String,
    val bgColors: List<Color>,
    val accentColor: Color,
    val icon: ImageVector,
    val ctaText: String,
    val liveServiceName: String? = null,
    val liveServiceUrl: String? = null,
    val targetTab: String = "Services"
)

private data class BlogPostItem(
    val id: String,
    val title: String,
    val summary: String,
    val category: String,
    val categoryColor: Color,
    val readTime: String,
    val publishDate: String,
    val icon: ImageVector,
    val keyTakeaways: List<String>,
    val fullArticle: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerHomeTab(
    viewModel: CustomerDashboardViewModel,
    userName: String,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onSelectTab: (String) -> Unit,
    onOpenProject: (String) -> Unit,
    onOpenLiveService: (String, String) -> Unit
) {
    val context = LocalContext.current
    var showSuggestions by remember { mutableStateOf(false) }

    val activeOrders = viewModel.orders.filter { it.status != "Completed" }
    val completedOrders = viewModel.orders.filter { it.status == "Completed" }
    val pendingActions = viewModel.orders.filter { order ->
        if (order.status == "Completed" || order.status == "Documents Verified" || order.status == "Processing at Portal") return@filter false
        if (order.status == "Waiting for Clarification") return@filter true
        if (order.status == "Pending Documents" || order.status == "Documents Required") {
            if (order.customerRequirements.isNotEmpty()) {
                return@filter order.customerRequirements.any { r ->
                    !r.isClientCompleted && r.uploadedDocumentUrl.isBlank() && r.documentUrl.isBlank() && r.clientValue.isBlank() && r.status != "Received" && r.status != "Verified"
                }
            }
            return@filter false
        }
        false
    }
    val unpaidOrders = viewModel.orders.filter { order ->
        order.status != "Completed" && (order.paymentStatus.equals("Pending", ignoreCase = true) || order.paymentStatus.equals("Partial", ignoreCase = true) || order.paymentStatus.equals("Unpaid", ignoreCase = true))
    }
    val totalOutstanding = unpaidOrders.sumOf { it.price.toLong() }
    val totalVolume = viewModel.orders.sumOf { it.price }

    val promoOffers = remember {
        listOf(
            PromoOfferItem(
                id = "offer-ccfs-2026",
                tag = "GOVERNMENT AMNESTY",
                title = "ROC CCFS-2026 Amnesty Scheme",
                description = "100% Late Filing Penalty Waiver for pending MCA returns. Clear years of default with zero additional fees.",
                badge = "LIMITED PERIOD",
                bgColors = listOf(DarkSlate, Color(0xFF831843)),
                accentColor = Color(0xFFF43F5E),
                icon = Icons.Default.AutoAwesome,
                ctaText = "Avail Scheme →",
                liveServiceName = "CCFS-2026 Scheme",
                liveServiceUrl = "https://vrhere.in/compliance-scheme-2026"
            ),
            PromoOfferItem(
                id = "offer-startup-80iac",
                tag = "TAX HOLIDAY",
                title = "Startup India & 80-IAC 3-Year Exemption",
                description = "Get 100% Income Tax Exemption for 3 consecutive years with DPIIT Recognition & IMB Certification.",
                badge = "DPIIT APPROVED",
                bgColors = listOf(DarkSlate, Color(0xFF065F46)),
                accentColor = Emerald500,
                icon = Icons.Default.RocketLaunch,
                ctaText = "Apply Now →",
                liveServiceName = "Startup India Registration",
                liveServiceUrl = "https://vrhere.in/startup-india"
            ),
            PromoOfferItem(
                id = "offer-pvt-ltd-pack",
                tag = "ALL-IN-ONE PACK",
                title = "Free GST + MSME with Pvt Ltd",
                description = "Complete incorporation with DIN, DSC, MOA, AOA, PAN, TAN, GSTIN & MSME Udyam registration included.",
                badge = "SAVE ₹4,999",
                bgColors = listOf(DarkSlate, Color(0xFF312E81)),
                accentColor = Indigo500,
                icon = Icons.Default.Business,
                ctaText = "Register Today →",
                liveServiceName = "Private Limited Registration",
                liveServiceUrl = "https://vrhere.in/pvt-ltd-registration"
            ),
            PromoOfferItem(
                id = "offer-iso-fasttrack",
                tag = "FAST-TRACK DISPATCH",
                title = "Fast-Track ISO 9001 / 27001",
                description = "Globally recognized IAF/UAF accredited certification delivered in 3 working days for tender eligibility.",
                badge = "3-DAY DISPATCH",
                bgColors = listOf(DarkSlate, Color(0xFF78350F)),
                accentColor = Amber500,
                icon = Icons.Default.Security,
                ctaText = "Get Certified →",
                targetTab = "Services"
            )
        )
    }

    val blogPosts = remember {
        listOf(
            BlogPostItem(
                id = "blog-mca-kyc-2026",
                title = "MCA Annual Returns & Director KYC: Mandatory Compliance Guide (FY 2025-26)",
                summary = "Complete roadmap on Form AOC-4, MGT-7, and DIR-3 KYC timelines to avoid director disqualification and ₹100/day penalties under the Companies Act.",
                category = "Corporate Law",
                categoryColor = Color(0xFF2563EB),
                readTime = "4 min read",
                publishDate = "Mar 2026",
                icon = Icons.Default.Business,
                keyTakeaways = listOf(
                    "DIR-3 KYC mandatory annually for all active DIN holders",
                    "AOC-4 (Financial Statements) due within 30 days of AGM",
                    "MGT-7 (Annual Return) due within 60 days of AGM",
                    "Late fee accumulates at ₹100 per day with no upper cap unless under amnesty"
                ),
                fullArticle = """
                    Every registered Private Limited and Public Limited Company in India is legally mandated to maintain active compliance with the Ministry of Corporate Affairs (MCA).
                    
                    1. DIR-3 KYC Filing:
                    Every individual holding a Director Identification Number (DIN) must complete Web KYC or e-Form DIR-3 KYC before the cutoff date. Failure to file leads to deactivation of DIN and a standard penalty of ₹5,000 per DIN.
                    
                    2. Form AOC-4 (Financial Statements):
                    Must include the Audited Balance Sheet, Profit & Loss Statement, Auditor's Report, and Director's Report. It must be filed within 30 days from the date of the Annual General Meeting (AGM).
                    
                    3. Form MGT-7 / MGT-7A (Annual Return):
                    Small companies can file MGT-7A, while other companies file MGT-7. This captures shareholding patterns, directorship changes, and board meetings held during the financial year.
                    
                    4. Impact of Non-Compliance:
                    Non-filing triggers disqualification of directors under Section 164(2) for 5 years and potential striking off by the ROC under Section 248. VR Here's corporate legal team handles end-to-end preparation and MCA portal filing.
                """.trimIndent()
            ),
            BlogPostItem(
                id = "blog-gst-einvoicing-itc",
                title = "GST E-Invoicing & ITC 2B Reconciliation: Avoiding Audit Notices",
                summary = "New strict audit rules on Form GSTR-1A, auto-generated GSTR-2B ITC matching, and avoiding 100% ITC disallowance under Section 16(2)(aa).",
                category = "GST & Taxation",
                categoryColor = Emerald500,
                readTime = "5 min read",
                publishDate = "Mar 2026",
                icon = Icons.Default.ReceiptLong,
                keyTakeaways = listOf(
                    "E-Invoicing mandatory for B2B transactions above ₹5 Cr threshold",
                    "Input Tax Credit (ITC) strictly restricted to invoices in GSTR-2B",
                    "Form GSTR-1A introduces pre-filing amendment facility",
                    "Automated Rule 88C / 88D notices issued for tax & ITC variances"
                ),
                fullArticle = """
                    The GST Network (GSTN) has rolled out rigorous automated reconciliation mechanisms that directly impact monthly cash flows and input tax credits.
                    
                    1. Mandatory E-Invoicing Thresholds:
                    Businesses with aggregate annual turnover exceeding ₹5 Crores must generate Invoice Reference Numbers (IRN) and signed QR codes via the IRP portal for all B2B invoices and debit/credit notes. Invoices without valid IRN are legally invalid.
                    
                    2. 100% GSTR-2B Matching Rule:
                    Under Section 16(2)(aa), no taxpayer can claim ITC unless the supplier has uploaded the invoice in their GSTR-1 and it is reflected in the recipient's GSTR-2B.
                    
                    3. Automated DRC-01B & DRC-01C Notices:
                    Variances between GSTR-1 vs GSTR-3B tax liability, or GSTR-2B vs GSTR-3B ITC claimed exceeding threshold percentages automatically generate DRC-01B/C notices requiring reconciliation within 7 days.
                    
                    4. Best Practices:
                    Run monthly supplier reconciliation reports, verify GSTIN statuses, and utilize VR Here Bookkeeping & GST Filing modules for automated verification.
                """.trimIndent()
            ),
            BlogPostItem(
                id = "blog-startup-india-80iac",
                title = "Startup India 80-IAC 3-Year Tax Holiday & IMB Approval Guide",
                summary = "Step-by-step checklist to secure Inter-Ministerial Board (IMB) approval for 100% income tax exemption and collateral-free bank funding.",
                category = "Startups & Funding",
                categoryColor = Indigo500,
                readTime = "6 min read",
                publishDate = "Feb 2026",
                icon = Icons.Default.RocketLaunch,
                keyTakeaways = listOf(
                    "100% tax exemption on profits for 3 consecutive years out of 10",
                    "Entity must be Private Limited or LLP incorporated after April 1, 2016",
                    "Turnover must not exceed ₹100 Crores in any financial year",
                    "Requires innovative business model approved by Inter-Ministerial Board"
                ),
                fullArticle = """
                    The Startup India initiative by the Department for Promotion of Industry and Internal Trade (DPIIT) offers transformative tax exemptions and funding benefits for eligible Indian startups.
                    
                    1. Section 80-IAC Benefits:
                    Eligible startups can choose a 3-consecutive-year 100% tax holiday from their first 10 years of incorporation. This frees substantial capital for reinvestment into product R&D, scaling operations, and hiring talent.
                    
                    2. Eligibility Criteria:
                    - Must be incorporated as a Private Limited Company or LLP.
                    - Turnover must not have exceeded ₹100 Crores in any previous year.
                    - Must be working towards innovation, development, or commercialization of new products or processes.
                    
                    3. Inter-Ministerial Board (IMB) Application:
                    DPIIT recognition is the first step; obtaining Section 80-IAC certification requires pitching business model uniqueness, patent/IP portfolios, and audited projections to the IMB committee.
                    
                    4. Additional Perks:
                    80% rebate on Patent filing fees, 50% rebate on Trademark fees, access to CGTMSE collateral-free credit guarantee loans up to ₹5 Crores, and self-certification under 6 labor and 3 environmental laws.
                """.trimIndent()
            ),
            BlogPostItem(
                id = "blog-trademark-classes",
                title = "Trademark Classes & Brand Protection: Preventing Infringement",
                summary = "How to accurately classify multi-class trademark applications (TM-A) across 45 NICE classes to protect logos, names, and software brands.",
                category = "IPR & Legal",
                categoryColor = Amber500,
                readTime = "3 min read",
                publishDate = "Feb 2026",
                icon = Icons.Default.Shield,
                keyTakeaways = listOf(
                    "45 NICE Classification classes (Classes 1-34 Goods, 35-45 Services)",
                    "Class 35 covers retail, wholesale, e-commerce, and digital marketplaces",
                    "Class 42 covers SaaS, software development, and cloud IT services",
                    "TM symbol can be used immediately on filing; ® only upon registration certificate"
                ),
                fullArticle = """
                    A trademark protects your unique brand identity, brand reputation, and prevents competitors from using deceptively similar names, logos, or slogans.
                    
                    1. The NICE Classification System:
                    Trademark applications are categorized into 45 distinct classes. Selecting incorrect classes leaves your actual core revenue streams vulnerable to competitor squatting and infringement.
                    
                    2. Key Classes for Modern Businesses:
                    - Class 35: Advertising, business management, retail, and e-commerce distribution.
                    - Class 42: Software as a Service (SaaS), IT solutions, technology hosting, and design.
                    - Class 9: Mobile applications, downloadable software, and electronics.
                    - Class 41: Education, training, entertainment, and digital media production.
                    
                    3. Registration Workflow:
                    Search Clearance → Form TM-A Filing → Examination Report (responding to objections under Section 9 & 11) → Journal Publication (4-month opposition period) → Registration Certificate issued for 10-year renewable term.
                    
                    4. Brand Defense:
                    VR Here provides end-to-end trademark search, objection drafting, hearing representation, and ongoing trademark monitoring to stop copycats immediately.
                """.trimIndent()
            )
        )
    }

    var selectedBlogPost by remember { mutableStateOf<BlogPostItem?>(null) }
    val pagerState = rememberPagerState(pageCount = { promoOffers.size })

    // Auto-slide Carousel timer (4 seconds)
    LaunchedEffect(pagerState) {
        while (true) {
            delay(4000)
            val nextPage = (pagerState.currentPage + 1) % promoOffers.size
            pagerState.animateScrollToPage(nextPage)
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)
    ) {
        // 1. TOP GREETING & SEARCH BAR WITH GLOWING BACKDROP
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Greeting text
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = "Welcome, ${userName.ifEmpty { "Valued Client" }}",
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Black,
                            color = TextDark,
                            letterSpacing = (-0.5).sp
                        )
                        Text(text = "👋", fontSize = 20.sp)
                    }
                    Text(
                        text = "Here is an executive snapshot of your filings, compliance status, and vault.",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }

                // Glowing Search Input Container matching Web
                Box(modifier = Modifier.fillMaxWidth()) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(6.dp, RoundedCornerShape(16.dp), ambientColor = PrimaryRed.copy(alpha = 0.15f), spotColor = PrimaryRed.copy(alpha = 0.25f)),
                        shape = RoundedCornerShape(16.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Search,
                                contentDescription = "Search",
                                tint = PrimaryRed,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            TextField(
                                value = searchQuery,
                                onValueChange = {
                                    onSearchQueryChange(it)
                                    showSuggestions = it.isNotBlank()
                                },
                                placeholder = {
                                    Text(
                                        "Search any service or filing...",
                                        fontSize = 12.5.sp,
                                        color = TextMuted
                                    )
                                },
                                colors = TextFieldDefaults.colors(
                                    focusedContainerColor = Color.Transparent,
                                    unfocusedContainerColor = Color.Transparent,
                                    disabledContainerColor = Color.Transparent,
                                    errorContainerColor = Color.Transparent,
                                    focusedIndicatorColor = Color.Transparent,
                                    unfocusedIndicatorColor = Color.Transparent,
                                    disabledIndicatorColor = Color.Transparent
                                ),
                                singleLine = true,
                                modifier = Modifier.weight(1f)
                            )
                            if (searchQuery.isNotBlank()) {
                                Button(
                                    onClick = {
                                        onSelectTab("Services")
                                        showSuggestions = false
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                                    shape = RoundedCornerShape(8.dp),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text("FIND", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color.White)
                                }
                            }
                        }
                    }
                }

                // Autocomplete Suggestions Dropdown
                if (showSuggestions && filteredSuggestions.isNotEmpty()) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(12.dp, RoundedCornerShape(16.dp)),
                        shape = RoundedCornerShape(16.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight)
                    ) {
                        Column(modifier = Modifier.padding(vertical = 6.dp)) {
                            filteredSuggestions.forEach { suggestion ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            val liveMap = mapOf(
                                                "Private Limited Company Registration" to Pair("Private Limited Registration", "https://vrhere.in/pvt-ltd-registration"),
                                                "Limited Liability Partnership (LLP)" to Pair("Partnership Firm", "https://vrhere.in/partnership-firm"),
                                                "GST Registration" to Pair("GST Registration", "https://vrhere.in/gst-registration"),
                                                "Income Tax Return" to Pair("Income Tax Return", "https://vrhere.in/income-tax-return"),
                                                "Company Annual Compliances" to Pair("CCFS-2026 Scheme", "https://vrhere.in/compliance-scheme-2026")
                                            )
                                            val matched = liveMap[suggestion]
                                            if (matched != null) {
                                                onOpenLiveService(matched.first, matched.second)
                                            } else {
                                                onSearchQueryChange(suggestion)
                                                onSelectTab("Services")
                                            }
                                            showSuggestions = false
                                        }
                                        .padding(horizontal = 16.dp, vertical = 10.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = suggestion,
                                        fontSize = 12.5.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = TextDark
                                    )
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                        contentDescription = null,
                                        tint = PrimaryRed,
                                        modifier = Modifier.size(14.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. 4-KPI STAT CARDS (EXECUTIVE OVERVIEW) MATCHING WEB 1:1
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // KPI 1: Active Orders
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Orders") },
                        shape = RoundedCornerShape(18.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("ACTIVE ORDERS", fontSize = 9.sp, fontWeight = FontWeight.Black, color = TextMuted, letterSpacing = 0.5.sp)
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(PrimaryRed.copy(alpha = 0.10f), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.Work, contentDescription = null, tint = PrimaryRed, modifier = Modifier.size(15.dp))
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                Text("${activeOrders.size}", fontSize = 22.sp, fontWeight = FontWeight.Black, color = TextDark)
                                Text("Track →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = PrimaryRed)
                            }
                            Text("In-progress filings", fontSize = 10.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                        }
                    }

                    // KPI 2: Action Needed
                    val hasPending = pendingActions.isNotEmpty()
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Orders") },
                        shape = RoundedCornerShape(18.dp),
                        color = if (hasPending) Color(0xFFFFF1F2) else Color.White,
                        border = BorderStroke(1.dp, if (hasPending) Color(0xFFFECDD3) else BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "ACTION NEEDED",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (hasPending) Color(0xFFE11D48) else TextMuted,
                                    letterSpacing = 0.5.sp
                                )
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(if (hasPending) Color(0xFFFFE4E6) else BgInput, RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = if (hasPending) Color(0xFFE11D48) else TextMuted,
                                        modifier = Modifier.size(15.dp)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                Text(
                                    "${pendingActions.size}",
                                    fontSize = 22.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (hasPending) Color(0xFFBE123C) else TextDark
                                )
                                Text(
                                    "Upload →",
                                    fontSize = 10.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (hasPending) Color(0xFFE11D48) else TextMuted
                                )
                            }
                            Text("Pending proofs", fontSize = 10.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // KPI 3: Digital Vault
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Vault") },
                        shape = RoundedCornerShape(18.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("DIGITAL VAULT", fontSize = 9.sp, fontWeight = FontWeight.Black, color = TextMuted, letterSpacing = 0.5.sp)
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(Emerald500.copy(alpha = 0.10f), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.Folder, contentDescription = null, tint = Emerald500, modifier = Modifier.size(15.dp))
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                val vaultCount = if (completedOrders.isNotEmpty()) completedOrders.size * 3 + 8 else 8
                                Text("$vaultCount", fontSize = 22.sp, fontWeight = FontWeight.Black, color = TextDark)
                                Text("Vault →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Emerald500)
                            }
                            Text("Verified documents", fontSize = 10.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                        }
                    }

                    // KPI 4: Total Portfolio / Due Balance
                    val hasDue = totalOutstanding > 0
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Invoices") },
                        shape = RoundedCornerShape(18.dp),
                        color = if (hasDue) Color(0xFFFFFBEB) else Color.White,
                        border = BorderStroke(1.dp, if (hasDue) Color(0xFFFDE68A) else BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    if (hasDue) "DUE BALANCE" else "TOTAL PORTFOLIO",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (hasDue) Amber500 else TextMuted,
                                    letterSpacing = 0.5.sp
                                )
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(if (hasDue) Color(0xFFFEF3C7) else Color(0xFF2563EB).copy(alpha = 0.10f), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        Icons.Default.CurrencyRupee,
                                        contentDescription = null,
                                        tint = if (hasDue) Amber500 else Color(0xFF2563EB),
                                        modifier = Modifier.size(15.dp)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                if (hasDue) {
                                    Text("₹${totalOutstanding}", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF92400E))
                                    Text("Pay →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Amber500)
                                } else {
                                    val volumeK = (totalVolume / 1000.0)
                                    Text("₹${"%.1f".format(volumeK)}k", fontSize = 22.sp, fontWeight = FontWeight.Black, color = TextDark)
                                    Text("Bills →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB))
                                }
                            }
                            Text(
                                if (hasDue) "${unpaidOrders.size} pending payment(s)" else "Settled volume",
                                fontSize = 10.sp,
                                color = TextMuted,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                    }
                }
            }
        }

        // 3. OFFERS & SPECIAL PROMOTIONS AUTO-SLIDING CAROUSEL BANNER
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(Icons.Default.LocalOffer, contentDescription = null, tint = PrimaryRed, modifier = Modifier.size(16.dp))
                        Text(
                            text = "Featured Offers & Schemes",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Black,
                            color = TextDark
                        )
                    }

                    // Dot Indicators
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        repeat(promoOffers.size) { index ->
                            val isSelected = pagerState.currentPage == index
                            Box(
                                modifier = Modifier
                                    .size(if (isSelected) 18.dp else 6.dp, 6.dp)
                                    .background(
                                        if (isSelected) PrimaryRed else BorderLight,
                                        RoundedCornerShape(3.dp)
                                    )
                            )
                        }
                    }
                }

                HorizontalPager(
                    state = pagerState,
                    modifier = Modifier.fillMaxWidth(),
                    pageSpacing = 12.dp
                ) { page ->
                    val offer = promoOffers[page]
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                            .clickable {
                                if (offer.liveServiceUrl != null && offer.liveServiceName != null) {
                                    onOpenLiveService(offer.liveServiceName, offer.liveServiceUrl)
                                } else {
                                    onSelectTab(offer.targetTab)
                                }
                            },
                        shape = RoundedCornerShape(22.dp),
                        color = offer.bgColors.first(),
                        border = BorderStroke(1.dp, offer.accentColor.copy(alpha = 0.35f)),
                        shadowElevation = 3.dp
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Brush.linearGradient(offer.bgColors))
                                .padding(18.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Surface(
                                        color = offer.accentColor.copy(alpha = 0.20f),
                                        border = BorderStroke(1.dp, offer.accentColor.copy(alpha = 0.45f)),
                                        shape = RoundedCornerShape(20.dp)
                                    ) {
                                        Text(
                                            text = offer.tag,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = offer.accentColor,
                                            letterSpacing = 0.8.sp,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                        )
                                    }

                                    Surface(
                                        color = Color.White.copy(alpha = 0.15f),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Text(
                                            text = offer.badge,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Color.White,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                        )
                                    }
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(46.dp)
                                            .background(offer.accentColor.copy(alpha = 0.20f), RoundedCornerShape(14.dp))
                                            .border(1.dp, offer.accentColor.copy(alpha = 0.35f), RoundedCornerShape(14.dp)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = offer.icon,
                                            contentDescription = null,
                                            tint = Color.White,
                                            modifier = Modifier.size(24.dp)
                                        )
                                    }

                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = offer.title,
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Color.White,
                                            lineHeight = 19.sp
                                        )
                                        Text(
                                            text = offer.description,
                                            fontSize = 11.sp,
                                            color = Slate400,
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis,
                                            lineHeight = 15.sp,
                                            modifier = Modifier.padding(top = 2.dp)
                                        )
                                    }
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "Tap to view eligibility & apply",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Slate400
                                    )

                                    Surface(
                                        color = offer.accentColor,
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Text(
                                                text = offer.ctaText,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Black,
                                                color = Color.White
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4. ENTERPRISE CLIENT HUB HERO BANNER MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(12.dp, RoundedCornerShape(24.dp), ambientColor = Color.Black.copy(alpha = 0.2f)),
                shape = RoundedCornerShape(24.dp),
                color = DarkSlate,
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.12f))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            color = PrimaryRed.copy(alpha = 0.25f),
                            border = BorderStroke(1.dp, PrimaryRed.copy(alpha = 0.4f)),
                            shape = RoundedCornerShape(20.dp)
                        ) {
                            Text(
                                text = "ENTERPRISE CLIENT HUB",
                                fontSize = 9.5.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFFFF8080),
                                letterSpacing = 0.8.sp,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Emerald500,
                                modifier = Modifier.size(13.dp)
                            )
                            Text(
                                text = "Real-Time MCA Sync",
                                fontSize = 10.5.sp,
                                fontWeight = FontWeight.Bold,
                                color = Slate400
                            )
                        }
                    }

                    Text(
                        text = "Manage Filings, Upload Vault Docs & Track Milestones",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = Color.White,
                        lineHeight = 22.sp
                    )

                    Text(
                        text = "All filings and compliance submissions are managed directly by your assigned dedicated advisor and operations team.",
                        fontSize = 11.5.sp,
                        color = Slate400,
                        lineHeight = 16.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = { onSelectTab("Orders") },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .weight(1f)
                                .scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text("View Pipeline (${activeOrders.size})", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(13.dp))
                            }
                        }

                        Button(
                            onClick = { onSelectTab("Services") },
                            colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.12f)),
                            border = BorderStroke(1.dp, Color.White.copy(alpha = 0.2f)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp)
                        ) {
                            Text("Catalog", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                }
            }
        }

        // 4.5 PENDING INVOICES & OUTSTANDING BALANCE ATTENTION CARD
        if (unpaidOrders.isNotEmpty()) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    color = Color(0xFFFEF2F2),
                    border = BorderStroke(1.dp, Color(0xFFFECDD3))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .background(PrimaryRed, RoundedCornerShape(10.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.AccountBalanceWallet, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                                }
                                Column {
                                    Text(
                                        text = "Pending Invoices & Payment Due",
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF991B1B)
                                    )
                                    Text(
                                        text = "Total Outstanding: ₹${totalOutstanding}",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = PrimaryRed
                                    )
                                }
                            }
                        }

                        unpaidOrders.take(3).forEach { order ->
                            val balanceDue = order.price.toLong()
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onOpenProject(order.id) },
                                shape = RoundedCornerShape(14.dp),
                                color = Color.White,
                                border = BorderStroke(1.dp, Color(0xFFFEE2E2))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(order.serviceName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark, maxLines = 1)
                                        Text("Balance Due: ₹$balanceDue", fontSize = 10.5.sp, fontWeight = FontWeight.Black, color = PrimaryRed)
                                    }
                                    Button(
                                        onClick = { onOpenProject(order.id) },
                                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                                        shape = RoundedCornerShape(10.dp),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                    ) {
                                        Text("Pay ₹$balanceDue", fontSize = 10.5.sp, fontWeight = FontWeight.Black, color = Color.White)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. ACTION ITEMS REQUIRING ATTENTION (IF ANY)
        if (pendingActions.isNotEmpty()) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    color = Color(0xFFFFFBEB),
                    border = BorderStroke(1.dp, Color(0xFFFDE68A))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Amber500, RoundedCornerShape(10.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Warning, contentDescription = null, tint = Color.Black, modifier = Modifier.size(18.dp))
                            }
                            Column {
                                Text(
                                    text = "Action Items Require Attention",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF78350F)
                                )
                                Text(
                                    text = "${pendingActions.size} order(s) waiting for document uploads or clarification.",
                                    fontSize = 10.5.sp,
                                    color = Color(0xFF92400E)
                                )
                            }
                        }

                        pendingActions.take(2).forEach { order ->
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onOpenProject(order.id) },
                                shape = RoundedCornerShape(12.dp),
                                color = Color.White,
                                border = BorderStroke(1.dp, Color(0xFFFDE68A))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(order.serviceName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                        Text(order.status, fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFFB45309))
                                    }
                                    Button(
                                        onClick = { onOpenProject(order.id) },
                                        colors = ButtonDefaults.buttonColors(containerColor = Amber500),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                    ) {
                                        Text("Take Action →", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color.Black)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. ACTIVE OPERATIONAL PIPELINE SNAPSHOT
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Active Operational Pipeline",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Black,
                            color = TextDark
                        )
                        Text(
                            text = "Live stage progress for ongoing filings",
                            fontSize = 11.sp,
                            color = TextMuted
                        )
                    }

                    Text(
                        text = "All Orders →",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = PrimaryRed,
                        modifier = Modifier
                            .clickable { onSelectTab("Orders") }
                            .scaleOnPress()
                    )
                }

                if (activeOrders.isEmpty()) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(18.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .background(BgInput, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Work, contentDescription = null, tint = TextMuted, modifier = Modifier.size(20.dp))
                            }
                            Text("No Active Engagements", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextDark)
                            Text(
                                "Explore our catalog to start a new company incorporation, GST, or compliance filing.",
                                fontSize = 11.sp,
                                color = TextMuted,
                                textAlign = TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Button(
                                onClick = { onSelectTab("Services") },
                                colors = ButtonDefaults.buttonColors(containerColor = DarkSlate),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Text("Browse Services", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                            }
                        }
                    }
                } else {
                    activeOrders.take(3).forEach { proj ->
                        val progress = getStatusProgress(proj.status)
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .scaleOnPress()
                                .clickable { onOpenProject(proj.id) },
                            shape = RoundedCornerShape(18.dp),
                            color = Color.White,
                            border = BorderStroke(1.dp, BorderLight),
                            shadowElevation = 1.dp
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = proj.serviceName,
                                            fontSize = 13.5.sp,
                                            fontWeight = FontWeight.Black,
                                            color = TextDark,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = proj.packageName.ifEmpty { "Standard Execution" },
                                            fontSize = 10.5.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = TextMuted
                                        )
                                    }
                                    StatusBadge(status = proj.status)
                                }

                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("MILESTONE PROGRESS", fontSize = 9.sp, fontWeight = FontWeight.Black, color = TextMuted, letterSpacing = 0.5.sp)
                                        Text("$progress%", fontSize = 10.5.sp, fontWeight = FontWeight.Black, color = PrimaryRed)
                                    }
                                    LinearProgressIndicator(
                                        progress = { progress / 100f },
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(5.dp)
                                            .clip(CircleShape),
                                        color = PrimaryRed,
                                        trackColor = BgInput
                                    )
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "ID: #${proj.id.takeLast(6).uppercase()}",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = TextMuted
                                    )
                                    Text(
                                        text = "Details →",
                                        fontSize = 10.5.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = PrimaryRed
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // 7. QUICK ACTION LAUNCHPAD (8 SERVICES BENTO GRID) MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                color = Color.White,
                border = BorderStroke(1.dp, BorderLight),
                shadowElevation = 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Quick Action Launchpad", fontSize = 15.sp, fontWeight = FontWeight.Black, color = TextDark)
                            Text("One-click jump to frequent requirements", fontSize = 11.sp, color = TextMuted)
                        }
                        Text(
                            "Catalog →",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = PrimaryRed,
                            modifier = Modifier
                                .clickable { onSelectTab("Services") }
                                .scaleOnPress()
                        )
                    }

                    // 4x2 Grid Layout
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        for (row in 0 until 2) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                for (col in 0 until 4) {
                                    val idx = row * 4 + col
                                    if (idx < topServices.size) {
                                        val service = topServices[idx]
                                        Surface(
                                            modifier = Modifier
                                                .weight(1f)
                                                .scaleOnPress()
                                                .clickable {
                                                    if (service.url != null) {
                                                        onOpenLiveService(service.name, service.url)
                                                    } else {
                                                        onSelectTab(service.key)
                                                    }
                                                },
                                            shape = RoundedCornerShape(14.dp),
                                            color = BgLight,
                                            border = BorderStroke(1.dp, BorderLight)
                                        ) {
                                            Column(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .padding(vertical = 12.dp, horizontal = 4.dp),
                                                horizontalAlignment = Alignment.CenterHorizontally,
                                                verticalArrangement = Arrangement.Center
                                            ) {
                                                Box(
                                                    modifier = Modifier
                                                        .size(42.dp)
                                                        .background(service.iconBg, RoundedCornerShape(12.dp)),
                                                    contentAlignment = Alignment.Center
                                                ) {
                                                    Icon(
                                                        imageVector = service.icon,
                                                        contentDescription = service.name,
                                                        tint = service.iconTint,
                                                        modifier = Modifier.size(20.dp)
                                                    )
                                                }
                                                Spacer(modifier = Modifier.height(6.dp))
                                                Text(
                                                    text = service.name,
                                                    fontSize = 10.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = TextDark,
                                                    textAlign = TextAlign.Center,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                                Text(
                                                    text = service.tag,
                                                    fontSize = 8.5.sp,
                                                    fontWeight = FontWeight.Medium,
                                                    color = TextMuted,
                                                    textAlign = TextAlign.Center,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 8. DEDICATED ADVISOR CARD MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = DarkSlate,
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.12f)),
                shadowElevation = 2.dp
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
                        Text(
                            "DEDICATED ADVISOR",
                            fontSize = 9.5.sp,
                            fontWeight = FontWeight.Black,
                            color = Slate400,
                            letterSpacing = 0.8.sp
                        )
                        Surface(
                            color = Emerald500.copy(alpha = 0.20f),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text(
                                "Available",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black,
                                color = Emerald500,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .background(
                                    Brush.linearGradient(listOf(Indigo500, Color(0xFF6366F1))),
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("CA", color = Color.White, fontWeight = FontWeight.Black, fontSize = 14.sp)
                        }
                        Column {
                            Text("Dedicated CA Advisory Team", fontSize = 13.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                            Text("Senior Chartered Accountant", fontSize = 11.sp, color = Slate400)
                        }
                    }

                    Text(
                        "Need priority clarification on your filing or requirements? Reach your dedicated advisor directly.",
                        fontSize = 11.5.sp,
                        color = Slate400,
                        lineHeight = 15.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = {
                                try {
                                    val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:918008530606"))
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Dialer not available", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.12f)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .weight(1f)
                                .scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Icon(Icons.Default.Phone, contentDescription = null, tint = Color.White, modifier = Modifier.size(13.dp))
                                Text("Call Advisor", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                            }
                        }

                        Button(
                            onClick = {
                                try {
                                    val url = "https://wa.me/918008530606"
                                    val i = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                    context.startActivity(i)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "WhatsApp not available", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .weight(1f)
                                .scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Text("WhatsApp", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                }
            }
        }

        // 9. STATUTORY COMPLIANCE CALENDAR MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = Color.White,
                border = BorderStroke(1.dp, BorderLight),
                shadowElevation = 1.dp
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
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(Icons.Default.CalendarMonth, contentDescription = null, tint = PrimaryRed, modifier = Modifier.size(16.dp))
                            Text("Compliance Calendar", fontSize = 13.sp, fontWeight = FontWeight.Black, color = TextDark)
                        }
                        Text("March 2026", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = TextMuted)
                    }

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        // Compliance 1
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = BgLight,
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("GST-3B Filing", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                    Text("Monthly Return", fontSize = 10.sp, color = TextMuted)
                                }
                                Surface(
                                    color = Color(0xFFFEF2F2),
                                    border = BorderStroke(1.dp, Color(0xFFFECACA)),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text("20th Mar", fontSize = 10.sp, fontWeight = FontWeight.Black, color = PrimaryRed, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }

                        // Compliance 2
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = BgLight,
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("Advance Tax Q4", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                    Text("Direct Tax Installment", fontSize = 10.sp, color = TextMuted)
                                }
                                Surface(
                                    color = Color(0xFFFFFBEB),
                                    border = BorderStroke(1.dp, Color(0xFFFDE68A)),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text("15th Mar", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Amber500, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }

                        // Compliance 3
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = BgLight,
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("CCFS-2026 Amnesty", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                    Text("ROC Late Filing Waiver", fontSize = 10.sp, color = TextMuted)
                                }
                                Surface(
                                    color = Color(0xFFECFDF5),
                                    border = BorderStroke(1.dp, Color(0xFFA7F3D0)),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text("Active", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Emerald500, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }
                    }
                }
            }
        }

        // 10. REFER & EARN REWARD CARD MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = Color(0xFFFFFBEB),
                border = BorderStroke(1.dp, Color(0xFFFDE68A)),
                shadowElevation = 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(Amber500, RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.CardGiftcard, contentDescription = null, tint = Color.White, modifier = Modifier.size(20.dp))
                        }
                        Column {
                            Text("Refer & Earn ₹500", fontSize = 13.5.sp, fontWeight = FontWeight.Black, color = Color(0xFF78350F))
                            Text("Instant wallet credits per referral", fontSize = 10.5.sp, color = Color(0xFF92400E))
                        }
                    }

                    Text(
                        "Refer another founder for company registration or ISO certification and receive ₹500 credit on your next filing.",
                        fontSize = 11.5.sp,
                        color = Color(0xFF78350F).copy(alpha = 0.85f),
                        lineHeight = 15.sp
                    )

                    Button(
                        onClick = { onSelectTab("Referrals") },
                        colors = ButtonDefaults.buttonColors(containerColor = DarkSlate),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                    ) {
                        Text("Get Referral Link", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
            }
        }

        // 11. LATEST REGULATORY UPDATES & INSIGHTS (BLOG SECTION)
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                color = Color.White,
                border = BorderStroke(1.dp, BorderLight),
                shadowElevation = 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Icon(Icons.Default.MenuBook, contentDescription = null, tint = PrimaryRed, modifier = Modifier.size(16.dp))
                                Text(
                                    text = "Compliance Insights & News",
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Black,
                                    color = TextDark
                                )
                            }
                            Text(
                                text = "Expert articles & statutory notifications",
                                fontSize = 11.sp,
                                color = TextMuted,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                    }

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        blogPosts.forEach { post ->
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .scaleOnPress()
                                    .clickable { selectedBlogPost = post },
                                shape = RoundedCornerShape(16.dp),
                                color = BgLight,
                                border = BorderStroke(1.dp, BorderLight)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(14.dp),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(42.dp)
                                            .background(post.categoryColor.copy(alpha = 0.12f), RoundedCornerShape(12.dp)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = post.icon,
                                            contentDescription = null,
                                            tint = post.categoryColor,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }

                                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Surface(
                                                color = post.categoryColor.copy(alpha = 0.12f),
                                                shape = RoundedCornerShape(6.dp)
                                            ) {
                                                Text(
                                                    text = post.category,
                                                    fontSize = 8.5.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = post.categoryColor,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }

                                            Row(
                                                verticalAlignment = Alignment.CenterVertically,
                                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                                            ) {
                                                Text(post.readTime, fontSize = 9.sp, fontWeight = FontWeight.Medium, color = TextMuted)
                                                Text("•", fontSize = 9.sp, color = TextMuted)
                                                Text(post.publishDate, fontSize = 9.sp, fontWeight = FontWeight.Medium, color = TextMuted)
                                            }
                                        }

                                        Text(
                                            text = post.title,
                                            fontSize = 12.5.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = TextDark,
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis,
                                            lineHeight = 16.sp
                                        )

                                        Text(
                                            text = post.summary,
                                            fontSize = 10.5.sp,
                                            color = TextMuted,
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis,
                                            lineHeight = 14.sp
                                        )

                                        Text(
                                            text = "Read Full Article →",
                                            fontSize = 10.5.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = PrimaryRed,
                                            modifier = Modifier.padding(top = 2.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 12. INTERACTIVE BLOG POST READER BOTTOM SHEET MODAL
    if (selectedBlogPost != null) {
        val post = selectedBlogPost!!
        ModalBottomSheet(
            onDismissRequest = { selectedBlogPost = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = Color.White,
            dragHandle = { BottomSheetDefaults.DragHandle() }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .fillMaxHeight(0.88f)
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                // Header tags
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(
                        color = post.categoryColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            text = post.category,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black,
                            color = post.categoryColor,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(post.readTime, fontSize = 10.5.sp, fontWeight = FontWeight.Medium, color = TextMuted)
                        Text("•", fontSize = 10.sp, color = TextMuted)
                        Text(post.publishDate, fontSize = 10.5.sp, fontWeight = FontWeight.Medium, color = TextMuted)
                    }
                }

                // Title
                Text(
                    text = post.title,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = TextDark,
                    lineHeight = 24.sp
                )

                Divider(color = BorderLight)

                // Scrollable Article Body
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    // Key Takeaways Callout Card
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = post.categoryColor.copy(alpha = 0.08f),
                            border = BorderStroke(1.dp, post.categoryColor.copy(alpha = 0.25f))
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = post.categoryColor, modifier = Modifier.size(16.dp))
                                    Text(
                                        text = "KEY TAKEAWAYS & ACTION POINTS",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        color = post.categoryColor,
                                        letterSpacing = 0.5.sp
                                    )
                                }

                                post.keyTakeaways.forEach { takeaway ->
                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                                        verticalAlignment = Alignment.Top
                                    ) {
                                        Text("•", fontSize = 12.sp, fontWeight = FontWeight.Black, color = post.categoryColor)
                                        Text(
                                            text = takeaway,
                                            fontSize = 11.5.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = TextDark,
                                            lineHeight = 16.sp
                                        )
                                    }
                                }
                            }
                        }
                    }

                    // Full Article Content
                    item {
                        Text(
                            text = post.fullArticle,
                            fontSize = 13.sp,
                            color = Slate600,
                            lineHeight = 21.sp,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }

                    // Advisory Contact Footer
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = DarkSlate
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    text = "Need assistance with this compliance?",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color.White
                                )
                                Text(
                                    text = "Our chartered accountants and legal advocates are ready to handle the filing on your behalf.",
                                    fontSize = 11.sp,
                                    color = Slate400,
                                    lineHeight = 15.sp
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Button(
                                    onClick = {
                                        selectedBlogPost = null
                                        onSelectTab("Services")
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Explore Filing Services", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
