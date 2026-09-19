package com.sbr.vrherebms.ui.screens.customer

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.components.VRLogoView
import com.sbr.vrherebms.ui.components.VRAvatarView
import com.sbr.vrherebms.ui.components.scaleOnPress
import com.sbr.vrherebms.ui.theme.*
import kotlinx.coroutines.launch

private data class SidebarNavItem(
    val id: String,
    val icon: ImageVector,
    val label: String,
    val badge: String? = null,
    val hasSubItems: Boolean = false
)

private data class SidebarNavGroup(
    val group: String,
    val items: List<SidebarNavItem>
)

@Composable
fun CustomerSidebarContent(
    userName: String,
    activeTab: String,
    profilePhoto: String? = null,
    companyName: String? = null,
    activeOrdersCount: Int = 0,
    unreadNotificationsCount: Int = 0,
    onTabSelected: (String) -> Unit,
    onLogout: () -> Unit,
    onCloseDrawer: () -> Unit
) {
    val context = LocalContext.current
    var isBookkeepingExpanded by remember { mutableStateOf(false) }

    val navGroups = remember(activeOrdersCount) {
        listOf(
            SidebarNavGroup(
                group = "Main Workspace",
                items = listOf(
                    SidebarNavItem("Home", Icons.Default.Dashboard, "Overview"),
                    SidebarNavItem("Services", Icons.Default.Work, "Service Catalog"),
                    SidebarNavItem(
                        id = "Orders",
                        icon = Icons.Default.ShoppingBag,
                        label = "Orders & Projects",
                        badge = if (activeOrdersCount > 0) "$activeOrdersCount" else null
                    ),
                    SidebarNavItem("Referrals", Icons.Default.CardGiftcard, "Refer & Earn", badge = "₹500"),
                    SidebarNavItem("Invoices", Icons.AutoMirrored.Filled.ReceiptLong, "Billing & Invoices")
                )
            ),
            SidebarNavGroup(
                group = "Compliance & Tools",
                items = listOf(
                    SidebarNavItem("Vault", Icons.Default.Folder, "Document Vault"),
                    SidebarNavItem("Bookkeeping", Icons.Default.Book, "Bookkeeping & AaaS", hasSubItems = true)
                )
            ),
            SidebarNavGroup(
                group = "Help & Settings",
                items = listOf(
                    SidebarNavItem("Support", Icons.Default.HeadsetMic, "Support & Tickets"),
                    SidebarNavItem("Account", Icons.Default.Person, "Account Settings")
                )
            )
        )
    }

    val bookkeepingSubItems = listOf(
        Pair("Executive Dashboard", Icons.Default.Dashboard),
        Pair("Sales Invoices", Icons.Default.Description),
        Pair("Purchase Bills", Icons.Default.ShoppingCart),
        Pair("Income & Expenses", Icons.Default.TrendingDown),
        Pair("Bank Statements", Icons.Default.AccountBalance),
        Pair("Customers & Vendors", Icons.Default.Apartment),
        Pair("Payroll & Timesheets", Icons.Default.People),
        Pair("Reports & P&L", Icons.Default.BarChart)
    )

    Column(
        modifier = Modifier
            .fillMaxHeight()
            .width(300.dp)
            .background(DarkSlate)
            .statusBarsPadding()
            .navigationBarsPadding()
    ) {
        // 1. Sidebar Brand Header matching Web
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color.White)
                .padding(horizontal = 18.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            VRLogoView(height = 28.dp, onClick = {
                onTabSelected("Home")
                onCloseDrawer()
            })

            IconButton(
                onClick = onCloseDrawer,
                modifier = Modifier
                    .size(32.dp)
                    .background(BgInput, CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Close Menu",
                    tint = TextDark,
                    modifier = Modifier.size(16.dp)
                )
            }
        }

        HorizontalDivider(color = BorderLight)

        // 2. Navigation Groups
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            navGroups.forEach { group ->
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    // Group Header
                    Text(
                        text = group.group.uppercase(),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        color = Slate400,
                        letterSpacing = 1.sp,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )

                    group.items.forEach { item ->
                        val isActive = activeTab == item.id

                        if (item.hasSubItems) {
                            Column {
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(12.dp))
                                        .clickable {
                                            if (isActive) {
                                                isBookkeepingExpanded = !isBookkeepingExpanded
                                            } else {
                                                onTabSelected(item.id)
                                                isBookkeepingExpanded = true
                                            }
                                        },
                                    color = if (isActive) PrimaryRed else Color.Transparent,
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(horizontal = 12.dp, vertical = 10.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                                        ) {
                                            Icon(
                                                imageVector = item.icon,
                                                contentDescription = item.label,
                                                tint = if (isActive) Color.White else Slate400,
                                                modifier = Modifier.size(18.dp)
                                            )
                                            Text(
                                                text = item.label,
                                                fontSize = 12.5.sp,
                                                fontWeight = if (isActive) FontWeight.Bold else FontWeight.Medium,
                                                color = if (isActive) Color.White else Color(0xFFE2E8F0)
                                            )
                                        }

                                        Icon(
                                            imageVector = if (isBookkeepingExpanded) Icons.Default.KeyboardArrowDown else Icons.Default.KeyboardArrowRight,
                                            contentDescription = null,
                                            tint = if (isActive) Color.White else Slate400,
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }

                                // Sub items accordion
                                AnimatedVisibility(
                                    visible = isBookkeepingExpanded,
                                    enter = expandVertically() + fadeIn(),
                                    exit = shrinkVertically() + fadeOut()
                                ) {
                                    Column(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(start = 24.dp, top = 4.dp, bottom = 4.dp)
                                            .border(
                                                BorderStroke(1.dp, Color.White.copy(alpha = 0.10f)),
                                                RoundedCornerShape(8.dp)
                                            )
                                            .padding(vertical = 4.dp),
                                        verticalArrangement = Arrangement.spacedBy(2.dp)
                                    ) {
                                        bookkeepingSubItems.forEach { (subLabel, subIcon) ->
                                            Row(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .clip(RoundedCornerShape(6.dp))
                                                    .clickable {
                                                        onTabSelected("Bookkeeping")
                                                        onCloseDrawer()
                                                    }
                                                    .padding(horizontal = 10.dp, vertical = 7.dp),
                                                verticalAlignment = Alignment.CenterVertically,
                                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                                            ) {
                                                Icon(
                                                    imageVector = subIcon,
                                                    contentDescription = subLabel,
                                                    tint = Slate400,
                                                    modifier = Modifier.size(14.dp)
                                                )
                                                Text(
                                                    text = subLabel,
                                                    fontSize = 11.sp,
                                                    color = Color(0xFFCBD5E1),
                                                    fontWeight = FontWeight.Medium
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .clickable {
                                        onTabSelected(item.id)
                                        onCloseDrawer()
                                    },
                                color = if (isActive) PrimaryRed else Color.Transparent,
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 10.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                                    ) {
                                        Icon(
                                            imageVector = item.icon,
                                            contentDescription = item.label,
                                            tint = if (isActive) Color.White else Slate400,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Text(
                                            text = item.label,
                                            fontSize = 12.5.sp,
                                            fontWeight = if (isActive) FontWeight.Bold else FontWeight.Medium,
                                            color = if (isActive) Color.White else Color(0xFFE2E8F0)
                                        )
                                    }

                                    if (item.badge != null) {
                                        Surface(
                                            color = if (isActive) Color.White else Amber500,
                                            shape = RoundedCornerShape(10.dp)
                                        ) {
                                            Text(
                                                text = item.badge,
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Black,
                                                color = if (isActive) PrimaryRed else Color.Black,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
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

        HorizontalDivider(color = Color.White.copy(alpha = 0.10f))

        // 3. Quick Direct Helpline & User Footer matching Web
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF0B1120))
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Direct Helpline Box
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        try {
                            val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:918008530606"))
                            context.startActivity(intent)
                        } catch (e: Exception) {
                            Toast.makeText(context, "Dialer not available", Toast.LENGTH_SHORT).show()
                        }
                    },
                shape = RoundedCornerShape(12.dp),
                color = Color(0xFF1E293B),
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.08f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .background(Indigo500.copy(alpha = 0.2f), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Phone,
                                contentDescription = "Helpline",
                                tint = Indigo400,
                                modifier = Modifier.size(15.dp)
                            )
                        }
                        Column {
                            Text(
                                text = "Direct Helpline",
                                fontSize = 11.5.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                            Text(
                                text = "+91 80085 30606",
                                fontSize = 10.sp,
                                color = Slate400
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .size(28.dp)
                            .background(Indigo500, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Phone,
                            contentDescription = "Call",
                            tint = Color.White,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
            }

            // User Info & Sign Out Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    modifier = Modifier
                        .weight(1f)
                        .clickable {
                            onTabSelected("Account")
                            onCloseDrawer()
                        },
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    VRAvatarView(
                        photoUrl = profilePhoto,
                        name = userName,
                        size = 36.dp,
                        borderWidth = 1.dp,
                        borderColor = Color.White.copy(alpha = 0.3f),
                        fontSize = 13.sp
                    )

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = userName.ifEmpty { "Customer" },
                            fontSize = 12.5.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = companyName?.ifBlank { null } ?: "Verified Customer",
                            fontSize = 10.sp,
                            color = Slate400,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                IconButton(
                    onClick = {
                        onCloseDrawer()
                        onLogout()
                    },
                    modifier = Modifier
                        .size(34.dp)
                        .background(PrimaryRed.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ExitToApp,
                        contentDescription = "Sign Out",
                        tint = Color(0xFFFF8080),
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}
