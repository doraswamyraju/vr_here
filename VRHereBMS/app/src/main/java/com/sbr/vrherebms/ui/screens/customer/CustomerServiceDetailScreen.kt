package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.ui.screens.customer.scaleOnPress
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.*

// --- SERVICE DETAIL MODEL DATA STRUCTURES ---
data class ServicePackage(
    val id: String,
    val name: String,
    val price: Double,
    val isAdjustable: Boolean = false,
    val isPopular: Boolean = false,
    val description: String,
    val features: List<String>,
    val creativeButtonText: String
)

data class ServiceDetail(
    val id: String,
    val title: String,
    val description: String,
    val icon: ImageVector,
    val packages: List<ServicePackage>
)

fun resolveComposeIcon(iconKey: String): ImageVector {
    return when (iconKey.lowercase()) {
        "apartment", "building" -> Icons.Default.Apartment
        "description", "file" -> Icons.Default.Description
        "people", "group" -> Icons.Default.People
        "calculate", "calculator" -> Icons.Default.Calculate
        "star" -> Icons.Default.Star
        "globe" -> Icons.Default.Language
        "zap" -> Icons.Default.FlashOn
        "phone" -> Icons.Default.Phone
        else -> Icons.Default.Work
    }
}

object ServiceCatalog {
    var items by mutableStateOf<Map<String, ServiceDetail>>(
        mapOf(
            "pvt-ltd-registration" to ServiceDetail(
                id = "pvt-ltd-registration",
                title = "Private Limited Registration",
                description = "Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.",
                icon = Icons.Default.Apartment,
                packages = listOf(
                    ServicePackage(
                        id = "consultation",
                        name = "Expert Consultation",
                        price = 499.0,
                        isAdjustable = true,
                        description = "Start here if you are unsure. Fee fully adjusted against registration.",
                        features = listOf("30 Mins CA/CS Call", "Business Structure Advice", "Name Availability Check", "Compliance Roadmap"),
                        creativeButtonText = "Consult CA/CS Now"
                    ),
                    ServicePackage(
                        id = "basic",
                        name = "Basic Plan",
                        price = 5499.0,
                        description = "Essential registration for verified startups.",
                        features = listOf("Name Approval (RUN)", "COI, PAN & TAN", "MOA & AOA", "2 DIN & 2 DSC", "PF/ESI/MSME registration"),
                        creativeButtonText = "Launch Basic Setup"
                    ),
                    ServicePackage(
                        id = "advance",
                        name = "Advance Plan",
                        price = 11399.0,
                        isPopular = true,
                        description = "Complete compliance & web presence.",
                        features = listOf("Everything in Basic", "GST Registration", "Import Export Code (IEC)", "ISO Certification", "Professional Website"),
                        creativeButtonText = "Unlock Premium Growth"
                    )
                )
            ),
            "gst-registration" to ServiceDetail(
                id = "gst-registration",
                title = "GST Registration",
                description = "Get your GST number quickly and start filing returns. Essential for businesses with turnover above thresholds.",
                icon = Icons.Default.Description,
                packages = listOf(
                    ServicePackage(
                        id = "consultation",
                        name = "Expert Consultation",
                        price = 499.0,
                        isAdjustable = true,
                        description = "Speak with our tax expert about your GST eligibility and documents.",
                        features = listOf("30 Mins Call", "Eligibility Check", "Documents List Review", "State-Specific Rules"),
                        creativeButtonText = "Speak with Tax Expert"
                    ),
                    ServicePackage(
                        id = "basic",
                        name = "Basic Plan",
                        price = 2569.0,
                        description = "Essential GST registration package.",
                        features = listOf("New GST Registration", "Updating Bank Account", "1st Month GST Return"),
                        creativeButtonText = "Get Registered Now"
                    ),
                    ServicePackage(
                        id = "expert",
                        name = "Expert Plan",
                        price = 9059.0,
                        isPopular = true,
                        description = "Complete tax compliance suite.",
                        features = listOf("Everything in Basic", "LUT Filing", "IEC Code Application", "2 Months GST Returns", "Priority Support"),
                        creativeButtonText = "Go Pro Compliance"
                    )
                )
            ),
            "partnership-firm" to ServiceDetail(
                id = "partnership-firm",
                title = "Partnership Firm Registration",
                description = "Ideal for small businesses with multiple owners. Shared responsibilities and faster decision making.",
                icon = Icons.Default.People,
                packages = listOf(
                    ServicePackage(
                        id = "consultation",
                        name = "Expert Consultation",
                        price = 499.0,
                        isAdjustable = true,
                        description = "Discuss partnership clauses and legal requirements with our experts.",
                        features = listOf("Partnership Deed Advice", "Clause Review", "Tax Implication Call"),
                        creativeButtonText = "Draft Partners Deed"
                    ),
                    ServicePackage(
                        id = "basic",
                        name = "Basic Plan",
                        price = 4899.0,
                        description = "Essential registration for partnership firms.",
                        features = listOf("Deed Drafting", "PAN & TAN Applications", "Firm Registration", "Notary Assistance"),
                        creativeButtonText = "Establish Partnership"
                    )
                )
            ),
            "income-tax-return" to ServiceDetail(
                id = "income-tax-return",
                title = "Income Tax Return (ITR)",
                description = "End-to-end ITR filing support for salaried, professionals, and businesses with compliance-first review.",
                icon = Icons.Default.Calculate,
                packages = listOf(
                    ServicePackage(
                        id = "consultation",
                        name = "Expert Consultation",
                        price = 499.0,
                        isAdjustable = true,
                        description = "Review your tax computation and self-assessment with a CA.",
                        features = listOf("Tax Planning Call", "Computation Review", "Deduction Guidance"),
                        creativeButtonText = "Solve Tax Doubts"
                    ),
                    ServicePackage(
                        id = "itr-filing",
                        name = "ITR Filing",
                        price = 1499.0,
                        isPopular = true,
                        description = "Standard filing service for individuals/professionals.",
                        features = listOf("ITR 1 to 4 Support", "Computation Review", "Notice Response Guidance"),
                        creativeButtonText = "Secure My Tax Filing"
                    )
                )
            )
        )
    )

    private val initialStaticCatalogMap = items

    fun updateFromApi(apiData: List<com.sbr.vrherebms.data.model.MobileServiceDetail>) {
        val updatedMap = initialStaticCatalogMap.toMutableMap()
        apiData.forEach { apiDetail ->
            val pkgs = apiDetail.packages.map { apiPkg ->
                ServicePackage(
                    id = apiPkg.id,
                    name = apiPkg.name,
                    price = apiPkg.price,
                    isAdjustable = apiPkg.isAdjustable,
                    isPopular = apiPkg.isPopular,
                    description = apiPkg.description,
                    features = apiPkg.features,
                    creativeButtonText = apiPkg.buttonText
                )
            }
            updatedMap[apiDetail.pageId] = ServiceDetail(
                id = apiDetail.pageId,
                title = apiDetail.title,
                description = apiDetail.description,
                icon = resolveComposeIcon(apiDetail.iconKey),
                packages = pkgs
            )
        }
        items = updatedMap
    }
}

@Composable
fun CreativePlanButton(
    pkg: ServicePackage,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "Breathe")
    val breatheScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.03f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "BreatheScale"
    )

    val scaleFactor = if (pkg.isPopular && isSelected) breatheScale else 1f

    val isConsultation = pkg.id == "consultation"
    val isPopular = pkg.isPopular

    val containerColor = when {
        isSelected && isPopular -> Color.Transparent
        isSelected -> Color(0xFF6366F1)
        isConsultation -> Color.White
        else -> Color(0xFFF1F5F9)
    }

    val contentColor = when {
        isSelected -> Color.White
        isConsultation -> Color(0xFF4F46E5)
        else -> Color(0xFF334155)
    }

    val borderStroke = when {
        isSelected -> null
        isConsultation -> BorderStroke(1.5.dp, Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFF8B5CF6))))
        else -> BorderStroke(1.dp, Color(0xFFE2E8F0))
    }

    val buttonModifier = Modifier
        .fillMaxWidth()
        .height(52.dp)
        .scaleOnPress()
        .graphicsLayer {
            this.scaleX = scaleFactor
            this.scaleY = scaleFactor
        }

    val shadowModifier = if (isSelected) {
        buttonModifier.shadow(
            elevation = 8.dp,
            shape = RoundedCornerShape(16.dp),
            clip = false,
            ambientColor = Color(0xFF6366F1).copy(alpha = 0.4f),
            spotColor = Color(0xFF6366F1).copy(alpha = 0.6f)
        )
    } else buttonModifier

    Box(
        modifier = shadowModifier
            .clip(RoundedCornerShape(16.dp))
            .then(
                if (isSelected && isPopular) {
                    Modifier.background(
                        brush = Brush.linearGradient(
                            colors = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6), Color(0xFFEC4899))
                        )
                    )
                } else {
                    Modifier.background(containerColor)
                }
            )
            .then(if (borderStroke != null) Modifier.border(borderStroke, RoundedCornerShape(16.dp)) else Modifier)
            .clickable { onClick() }
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                val icon = when {
                    isConsultation -> Icons.Default.ChatBubble
                    isPopular -> Icons.Default.Star
                    else -> Icons.Default.PlayArrow
                }
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = contentColor,
                    modifier = Modifier.size(13.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = pkg.creativeButtonText.uppercase(),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.sp,
                    color = contentColor
                )
            }
            
            val subtext = when {
                isConsultation -> "100% Refundable Setup Credit"
                isPopular -> "Best Value - Complete Compliance"
                else -> "Essential Package Setup"
            }
            Text(
                text = subtext.uppercase(),
                fontSize = 7.5.sp,
                fontWeight = FontWeight.Black,
                color = contentColor.copy(alpha = 0.8f),
                letterSpacing = 0.5.sp
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerServiceDetailScreen(
    serviceKey: String,
    onBackClick: () -> Unit,
    onCheckoutClick: (serviceTitle: String, selectedPlan: ServicePackage, clientName: String, clientEmail: String, clientPhone: String) -> Unit,
    onNeedAdviceClick: () -> Unit
) {
    val context = LocalContext.current
    val sessionManager = remember { SessionManager(context) }
    val service = remember(serviceKey) { ServiceCatalog.items[serviceKey] }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()

    if (service == null) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Service catalog item not found", fontWeight = FontWeight.Bold, color = Color.Gray)
                Spacer(modifier = Modifier.height(16.dp))
                Button(onClick = onBackClick) {
                    Text("Go Back")
                }
            }
        }
        return
    }

    var selectedPackage by remember { mutableStateOf(service.packages.first()) }
    var isConfirmSheetOpen by remember { mutableStateOf(false) }

    val density = LocalDensity.current
    val selectedElevation = remember(density) { with(density) { 12.dp.toPx() } }
    val normalElevation = remember(density) { with(density) { 4.dp.toPx() } }

    // Synchronize package selection with active viewport centered scroll position in real-time
    LaunchedEffect(listState.isScrollInProgress) {
        if (listState.isScrollInProgress) {
            snapshotFlow { listState.layoutInfo.visibleItemsInfo }
                .collect { visibleItems ->
                    if (visibleItems.isNotEmpty()) {
                        val packageIndices = service.packages.indices.map { it + 2 }
                        val visiblePackages = visibleItems.filter { it.index in packageIndices }
                        if (visiblePackages.isNotEmpty()) {
                            val viewportCenter = (listState.layoutInfo.viewportStartOffset + listState.layoutInfo.viewportEndOffset) / 2
                            val closest = visiblePackages.minByOrNull {
                                val cardCenter = it.offset + it.size / 2
                                kotlin.math.abs(cardCenter - viewportCenter)
                            }
                            closest?.let {
                                selectedPackage = service.packages[it.index - 2]
                            }
                        }
                    }
                }
        }
    }

    // Prefill form states
    var clientName by remember { mutableStateOf(sessionManager.getUserName() ?: "") }
    var clientEmail by remember { mutableStateOf(sessionManager.getUserEmail() ?: "") }
    var clientPhone by remember { mutableStateOf(sessionManager.getPhone()) }
    var termsAccepted by remember { mutableStateOf(false) }

    fun formatCurrency(amount: Double): String {
        val format = NumberFormat.getCurrencyInstance(Locale("en", "IN"))
        format.maximumFractionDigits = 0
        return format.format(amount)
    }

    Box(modifier = Modifier.fillMaxSize().background(Color(0xFFF8FAFC))) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(top = 16.dp, bottom = 140.dp) // extra padding to clear sticky checkout bottom bar
        ) {
            // Header back-bar & title
            item {
                Column(modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
                    Row(
                        modifier = Modifier
                            .clickable { onBackClick() }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back",
                            tint = Color(0xFF64748B),
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "MASTER CATALOG",
                            color = Color(0xFF64748B),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 1.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .background(
                                    brush = Brush.linearGradient(
                                        colors = listOf(Color(0xFF8B5CF6), Color(0xFF6366F1))
                                    ),
                                    shape = RoundedCornerShape(16.dp)
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = service.icon,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(28.dp)
                            )
                        }

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = service.title,
                                fontSize = 24.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A),
                                letterSpacing = (-0.5).sp,
                                lineHeight = 28.sp
                            )
                            Text(
                                text = service.description,
                                fontSize = 13.sp,
                                color = Color(0xFF475569),
                                modifier = Modifier.padding(top = 4.dp),
                                lineHeight = 18.sp
                            )
                        }
                    }
                }
            }

            // Divider
            item {
                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0xFFE2E8F0),
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 20.dp)
                )
            }

            // Package Plan Cards
            items(service.packages) { pkg ->
                val isSelected = selectedPackage.id == pkg.id
                
                // Card Border and Background Glowing Colors based on selection & recommended status
                val borderBrush = if (pkg.isPopular) {
                    Brush.linearGradient(
                        colors = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6), Color(0xFFEC4899))
                    )
                } else if (isSelected) {
                    Brush.linearGradient(colors = listOf(Color(0xFF6366F1), Color(0xFF4F46E5)))
                } else {
                    Brush.linearGradient(colors = listOf(Color(0xFFE2E8F0), Color(0xFFE2E8F0)))
                }

                val cardBgColor = if (isSelected) Color(0xFFFDFDFD) else Color.White

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 10.dp)
                        .clickable { selectedPackage = pkg }
                        .graphicsLayer {
                            this.shadowElevation = if (isSelected) selectedElevation else normalElevation
                            this.shape = RoundedCornerShape(28.dp)
                            this.clip = true
                        }
                        .border(
                            width = if (isSelected || pkg.isPopular) 2.dp else 1.dp,
                            brush = borderBrush,
                            shape = RoundedCornerShape(28.dp)
                        ),
                    colors = CardDefaults.cardColors(containerColor = cardBgColor)
                ) {
                    Box(modifier = Modifier.fillMaxWidth()) {
                        // Recommended Badge
                        if (pkg.isPopular) {
                            Box(
                                modifier = Modifier
                                    .align(Alignment.TopEnd)
                                    .background(
                                        brush = Brush.horizontalGradient(
                                            colors = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6))
                                        ),
                                        shape = RoundedCornerShape(bottomStart = 16.dp)
                                    )
                                    .padding(horizontal = 14.dp, vertical = 6.dp)
                            ) {
                                Text(
                                    text = "RECOMMENDED",
                                    color = Color.White,
                                    fontSize = 8.5.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 1.sp
                                )
                            }
                        }

                        Column(modifier = Modifier.padding(24.dp)) {
                            // Title & Indicator selection ring
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth().padding(end = if (pkg.isPopular) 80.dp else 0.dp)
                            ) {
                                Text(
                                    text = pkg.name,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF0F172A)
                                )

                                Box(
                                    modifier = Modifier
                                        .size(20.dp)
                                        .border(
                                            width = 2.dp,
                                            color = if (isSelected) Color(0xFF6366F1) else Color(0xFFCBD5E1),
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    if (isSelected) {
                                        Box(
                                            modifier = Modifier
                                                .size(10.dp)
                                                .background(Color(0xFF6366F1), CircleShape)
                                        )
                                    }
                                }
                            }

                            // Price block
                            Row(
                                modifier = Modifier.padding(vertical = 12.dp),
                                verticalAlignment = Alignment.Bottom
                            ) {
                                Text(
                                    text = formatCurrency(pkg.price),
                                    fontSize = 28.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF0F172A),
                                    letterSpacing = (-0.5).sp
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = if (pkg.isAdjustable) "(Adjustable)" else "+ Taxes",
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (pkg.isAdjustable) Color(0xFF6366F1) else Color(0xFF94A3B8),
                                    letterSpacing = 0.5.sp,
                                    modifier = Modifier.padding(bottom = 4.dp)
                                )
                            }

                            // Adjustable tag banner
                            if (pkg.isAdjustable) {
                                Row(
                                    modifier = Modifier
                                        .background(Color(0xFFEEF2F6), RoundedCornerShape(8.dp))
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                        .padding(bottom = 2.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Refresh,
                                        contentDescription = null,
                                        tint = Color(0xFF6366F1),
                                        modifier = Modifier.size(12.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "FULLY ADJUSTABLE AGAINST REGISTRATION",
                                        color = Color(0xFF4F46E5),
                                        fontSize = 8.5.sp,
                                        fontWeight = FontWeight.Black,
                                        letterSpacing = 0.5.sp
                                    )
                                }
                                Spacer(modifier = Modifier.height(12.dp))
                            }

                            Text(
                                text = pkg.description,
                                fontSize = 12.sp,
                                color = Color(0xFF64748B),
                                lineHeight = 16.sp,
                                modifier = Modifier.padding(bottom = 16.dp)
                            )

                            // Feature lists with beautiful green checkmarks
                            Column(
                                modifier = Modifier.padding(bottom = 20.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                pkg.features.forEach { feat ->
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.CheckCircle,
                                            contentDescription = null,
                                            tint = Color(0xFF10B981),
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(10.dp))
                                        Text(
                                            text = feat,
                                            fontSize = 12.sp,
                                            color = Color(0xFF334155),
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }

                            // Dynamic Creative Plan Buttons
                            CreativePlanButton(
                                pkg = pkg,
                                isSelected = isSelected,
                                onClick = {
                                    selectedPackage = pkg
                                    isConfirmSheetOpen = true
                                }
                            )
                        }
                    }
                }
            }

            // VR HERE Advantage section (CA/CS Oversight, real-time tracking, free advice)
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 20.dp),
                    shape = RoundedCornerShape(32.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
                ) {
                    Box(modifier = Modifier.fillMaxWidth()) {
                        // Background gradient blur mesh
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .size(140.dp)
                                .background(
                                    brush = Brush.radialGradient(
                                        colors = listOf(Color(0xFF6366F1).copy(alpha = 0.15f), Color.Transparent)
                                    )
                                )
                        )

                        Column(modifier = Modifier.padding(24.dp)) {
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFF1E293B), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 10.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = "THE VR HERE ADVANTAGE",
                                    color = Color(0xFF818CF8),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 1.sp
                                )
                            }

                            Spacer(modifier = Modifier.height(14.dp))
                            Text(
                                text = "Expert-Led Compliance & Seamless Execution",
                                color = Color.White,
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = (-0.5).sp,
                                lineHeight = 24.sp
                            )
                            Spacer(modifier = Modifier.height(18.dp))

                            // Bullet checklist
                            val advantages = listOf(
                                Pair("CA/CS Expert Oversight", "Every single filing is strictly reviewed for accuracy and regulatory compliance."),
                                Pair("Real-time Active Portal Tracking", "Monitor every step, milestone, and document progress directly in this app dashboard."),
                                Pair("Lifetime Post-Registration Support", "We assist in post-setup compliances, payroll structure, accounting, and licensing.")
                            )

                            advantages.forEach { (title, desc) ->
                                Row(
                                    modifier = Modifier.padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(28.dp)
                                            .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(8.dp)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Star,
                                            contentDescription = null,
                                            tint = Color(0xFFFBBF24),
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(14.dp))
                                    Column {
                                        Text(
                                            text = title,
                                            color = Color.White,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Text(
                                            text = desc,
                                            color = Color(0xFF94A3B8),
                                            fontSize = 11.sp,
                                            lineHeight = 15.sp,
                                            modifier = Modifier.padding(top = 2.dp)
                                        )
                                    }
                                }
                            }

                            HorizontalDivider(
                                thickness = 1.dp,
                                color = Color(0xFF1E293B),
                                modifier = Modifier.padding(vertical = 18.dp)
                            )

                            // Confused? Free Assessment section
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color.White.copy(alpha = 0.03f), RoundedCornerShape(20.dp))
                                    .border(1.dp, Color.White.copy(alpha = 0.05f), RoundedCornerShape(20.dp))
                                    .padding(20.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Info,
                                    contentDescription = null,
                                    tint = Color(0xFF818CF8),
                                    modifier = Modifier.size(32.dp)
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "Confused? Get Free Assessment",
                                    color = Color.White,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Black
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "Not sure which registration structure fits your needs? Raise a consultation support ticket in 1 tap for free advice.",
                                    color = Color(0xFF94A3B8),
                                    fontSize = 11.sp,
                                    textAlign = TextAlign.Center,
                                    lineHeight = 15.sp,
                                    modifier = Modifier.padding(horizontal = 8.dp)
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                                Button(
                                    onClick = onNeedAdviceClick,
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Color(0xFF0F172A)),
                                    modifier = Modifier.scaleOnPress()
                                ) {
                                    Text(
                                        text = "TALK TO EXPERT",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        letterSpacing = 1.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- STICKY CONVERSION CHECKOUT BOTTOM BAR ---
        // Highly dynamic glassmorphic checkout bottom panel replacing standard tab bar
        Box(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(Color.Transparent, Color(0xFFF8FAFC).copy(alpha = 0.95f), Color(0xFFF8FAFC))
                    )
                )
                .padding(horizontal = 16.dp, vertical = 20.dp),
            contentAlignment = Alignment.BottomCenter
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(90.dp)
                    .shadow(
                        elevation = 16.dp,
                        shape = RoundedCornerShape(24.dp),
                        clip = false,
                        ambientColor = Color(0xFF6366F1).copy(alpha = 0.25f),
                        spotColor = Color(0xFF6366F1).copy(alpha = 0.45f)
                    ),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                border = BorderStroke(
                    width = 1.dp,
                    brush = Brush.horizontalGradient(
                        colors = listOf(Color(0xFF6366F1).copy(alpha = 0.5f), Color(0xFF8B5CF6).copy(alpha = 0.5f))
                    )
                )
            ) {
                var isDropdownExpanded by remember { mutableStateOf(false) }

                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Left Side: Box showing package name with a Dropdown option
                    Box(
                        modifier = Modifier
                            .weight(1.3f)
                            .height(48.dp)
                            .background(Color(0xFF1E293B), RoundedCornerShape(14.dp))
                            .border(1.dp, Color(0xFF334155), RoundedCornerShape(14.dp))
                            .clickable { isDropdownExpanded = true }
                            .padding(horizontal = 12.dp),
                        contentAlignment = Alignment.CenterStart
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "SELECTED PLAN",
                                    color = Color(0xFF94A3B8),
                                    fontSize = 7.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 0.5.sp
                                )
                                Text(
                                    text = selectedPackage.name.uppercase(),
                                    color = Color.White,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Icon(
                                imageVector = Icons.Default.ArrowDropDown,
                                contentDescription = "Select Package",
                                tint = Color(0xFF6366F1),
                                modifier = Modifier.size(24.dp)
                            )
                        }

                        DropdownMenu(
                            expanded = isDropdownExpanded,
                            onDismissRequest = { isDropdownExpanded = false },
                            modifier = Modifier
                                .background(Color(0xFF0F172A))
                                .border(1.dp, Color(0xFF334155), RoundedCornerShape(12.dp))
                        ) {
                            service.packages.forEach { pkg ->
                                val isActive = selectedPackage.id == pkg.id
                                DropdownMenuItem(
                                    text = {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = pkg.name.uppercase(),
                                                color = if (isActive) Color(0xFF818CF8) else Color.White,
                                                fontWeight = FontWeight.Black,
                                                fontSize = 11.sp,
                                                letterSpacing = 0.5.sp
                                            )
                                            Spacer(modifier = Modifier.width(16.dp))
                                            Text(
                                                text = formatCurrency(pkg.price),
                                                color = if (isActive) Color(0xFF818CF8) else Color(0xFF94A3B8),
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 11.sp
                                            )
                                        }
                                    },
                                    onClick = {
                                        selectedPackage = pkg
                                        isDropdownExpanded = false
                                        val idx = service.packages.indexOf(pkg)
                                        scope.launch {
                                            listState.animateScrollToItem(idx + 2)
                                        }
                                    }
                                )
                            }
                        }
                    }

                    // Right Side: Action CTA Button showing price
                    Button(
                        onClick = { isConfirmSheetOpen = true },
                        modifier = Modifier
                            .weight(1.7f)
                            .height(48.dp)
                            .scaleOnPress()
                            .shadow(
                                elevation = 8.dp,
                                shape = RoundedCornerShape(14.dp),
                                clip = false,
                                ambientColor = Color(0xFF6366F1).copy(alpha = 0.4f),
                                spotColor = Color(0xFF6366F1).copy(alpha = 0.6f)
                            ),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF6366F1),
                            contentColor = Color.White
                        )
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            val btnLabel = when {
                                selectedPackage.id == "consultation" -> "CONSULT"
                                else -> "BOOK"
                            }
                            Text(
                                text = "$btnLabel @ ${formatCurrency(selectedPackage.price)}",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = 0.5.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Icon(
                                imageVector = Icons.Default.ArrowForward,
                                contentDescription = null,
                                modifier = Modifier.size(12.dp)
                            )
                        }
                    }
                }
            }

            // Pulsating Urgency / Social Proof capsule overlapping Card top
            Row(
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .offset(y = (-11).dp)
                    .background(
                        brush = Brush.horizontalGradient(
                            colors = listOf(Color(0xFFEF4444), Color(0xFFF43F5E))
                        ),
                        shape = RoundedCornerShape(12.dp)
                    )
                    .border(
                        width = 1.dp,
                        color = Color.White.copy(alpha = 0.25f),
                        shape = RoundedCornerShape(12.dp)
                    )
                    .padding(horizontal = 10.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                val dotTransition = rememberInfiniteTransition(label = "PulsingDot")
                val dotAlpha by dotTransition.animateFloat(
                    initialValue = 0.4f,
                    targetValue = 1f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(800, easing = FastOutSlowInEasing),
                        repeatMode = RepeatMode.Reverse
                    ),
                    label = "DotAlpha"
                )
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .graphicsLayer { alpha = dotAlpha }
                        .background(Color.White, CircleShape)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = if (selectedPackage.isPopular) {
                        "🔥 28 FOUNDERS REGISTERED TODAY!"
                    } else if (service.packages.size == 1) {
                        "⚡ LIMITED SPECIAL INAUGURAL PRICE!"
                    } else {
                        "⚡ 99.4% CLIENT SATISFACTION RATING"
                    },
                    color = Color.White,
                    fontSize = 8.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 0.5.sp
                )
            }
        }

        // --- PREFILLED CHECKOUT BOTTOM SHEET DIALOG ---
        if (isConfirmSheetOpen) {
            ModalBottomSheet(
                onDismissRequest = { isConfirmSheetOpen = false },
                containerColor = Color.White,
                shape = RoundedCornerShape(topStart = 32.dp, topEnd = 32.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp)
                        .padding(bottom = 40.dp)
                ) {
                    Text(
                        text = "Confirm Purchase Details",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF0F172A),
                        letterSpacing = (-0.5).sp
                    )
                    Text(
                        text = "Review and confirm contact info for portal document updates.",
                        fontSize = 12.sp,
                        color = Color(0xFF64748B),
                        modifier = Modifier.padding(top = 2.dp)
                    )

                    Spacer(modifier = Modifier.height(20.dp))

                    // Selected Item Summary
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    text = service.title,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF6366F1),
                                    letterSpacing = 0.5.sp
                                )
                                Text(
                                    text = selectedPackage.name,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF0F172A)
                                )
                            }
                            Text(
                                text = formatCurrency(selectedPackage.price),
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(20.dp))

                    // Prefilled Input Form
                    Text(
                        text = "YOUR CONTACT INFORMATION",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF94A3B8),
                        letterSpacing = 1.sp,
                        modifier = Modifier.padding(bottom = 6.dp)
                    )

                    OutlinedTextField(
                        value = clientName,
                        onValueChange = { clientName = it },
                        label = { Text("Name", fontSize = 12.sp) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF6366F1),
                            unfocusedBorderColor = Color(0xFFCBD5E1)
                        ),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                    )

                    OutlinedTextField(
                        value = clientEmail,
                        onValueChange = { clientEmail = it },
                        label = { Text("Email Address", fontSize = 12.sp) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF6366F1),
                            unfocusedBorderColor = Color(0xFFCBD5E1)
                        ),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                    )

                    OutlinedTextField(
                        value = clientPhone,
                        onValueChange = { clientPhone = it },
                        label = { Text("Phone Number", fontSize = 12.sp) },
                        placeholder = { Text("10-Digit Mobile", color = Color.LightGray) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                        shape = RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF6366F1),
                            unfocusedBorderColor = Color(0xFFCBD5E1)
                        ),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    // Terms and Conditions checkbox
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { termsAccepted = !termsAccepted }
                            .padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = termsAccepted,
                            onCheckedChange = { termsAccepted = it },
                            colors = CheckboxDefaults.colors(checkedColor = Color(0xFF6366F1))
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "I accept the Terms and Conditions of service execution.",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF475569)
                        )
                    }

                    Spacer(modifier = Modifier.height(20.dp))

                    // Big glowing Proceed to checkout call
                    Button(
                        onClick = {
                            if (clientName.isBlank() || clientEmail.isBlank() || clientPhone.isBlank()) {
                                return@Button
                            }
                            if (!termsAccepted) {
                                return@Button
                            }
                            // Save phone locally for convenience
                            sessionManager.savePhone(clientPhone)
                            
                            isConfirmSheetOpen = false
                            // Fire the checkout trigger!
                            onCheckoutClick(service.title, selectedPackage, clientName, clientEmail, clientPhone)
                        },
                        enabled = clientName.isNotBlank() && clientEmail.isNotBlank() && clientPhone.isNotBlank() && termsAccepted,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .scaleOnPress()
                            .shadow(
                                elevation = 12.dp,
                                shape = RoundedCornerShape(16.dp),
                                clip = false,
                                ambientColor = Color(0xFF6366F1).copy(alpha = 0.4f),
                                spotColor = Color(0xFF6366F1).copy(alpha = 0.6f)
                            ),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF6366F1),
                            contentColor = Color.White,
                            disabledContainerColor = Color(0xFFE2E8F0),
                            disabledContentColor = Color(0xFF94A3B8)
                        )
                    ) {
                        Text(
                            text = "PROCEED TO SECURE CHECKOUT",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 1.sp
                        )
                    }
                }
            }
        }
    }
}
