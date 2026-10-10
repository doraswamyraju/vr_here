package com.sbr.vrherebms.ui.components

import androidx.compose.animation.*
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
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
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.composed
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.Image
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import coil.compose.SubcomposeAsyncImage
import com.sbr.vrherebms.R
import com.sbr.vrherebms.data.model.NotificationResponse
import com.sbr.vrherebms.ui.theme.*

/**
 * Format profile image URLs (Google Drive links, relative backend URLs, etc.)
 */
fun formatImageUrl(url: String?): String? {
    if (url.isNullOrBlank()) return null
    val trimmed = url.trim()
    if (trimmed.contains("drive.google.com/file/d/")) {
        val match = Regex("""/file/d/([a-zA-Z0-9_-]+)""").find(trimmed)
        if (match != null && match.groupValues.size > 1) {
            return "https://lh3.googleusercontent.com/d/${match.groupValues[1]}"
        }
    }
    if (trimmed.contains("drive.google.com/open?id=")) {
        val match = Regex("""id=([a-zA-Z0-9_-]+)""").find(trimmed)
        if (match != null && match.groupValues.size > 1) {
            return "https://lh3.googleusercontent.com/d/${match.groupValues[1]}"
        }
    }
    if (trimmed.startsWith("/")) {
        val base = com.sbr.vrherebms.data.remote.VRHereAPI.BASE_URL.removeSuffix("/").removeSuffix("/api")
        return "$base$trimmed"
    }
    return trimmed
}

/**
 * Modern Avatar View with async image loading and styled initials fallback
 */
@Composable
fun VRAvatarView(
    photoUrl: String? = null,
    name: String = "",
    size: androidx.compose.ui.unit.Dp = 36.dp,
    shape: androidx.compose.ui.graphics.Shape = CircleShape,
    borderColor: Color = Color.White.copy(alpha = 0.3f),
    borderWidth: androidx.compose.ui.unit.Dp = 1.dp,
    fontSize: androidx.compose.ui.unit.TextUnit = 13.sp,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null
) {
    val formattedUrl = remember(photoUrl) { formatImageUrl(photoUrl) }
    val initials = remember(name) {
        val parts = name.trim().split(" ").filter { it.isNotBlank() }
        if (parts.isEmpty()) "C"
        else if (parts.size == 1) parts[0].take(1).uppercase()
        else (parts[0].take(1) + parts[1].take(1)).uppercase()
    }

    val clickModifier = if (onClick != null) {
        Modifier.scaleOnPress().clickable { onClick() }
    } else Modifier

    Box(
        modifier = modifier
            .size(size)
            .clip(shape)
            .border(borderWidth, borderColor, shape)
            .then(clickModifier),
        contentAlignment = Alignment.Center
    ) {
        if (!formattedUrl.isNullOrBlank()) {
            SubcomposeAsyncImage(
                model = formattedUrl,
                contentDescription = name.ifEmpty { "Profile Avatar" },
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
                loading = {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(Brush.linearGradient(listOf(Indigo500, Indigo600))),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = initials,
                            color = Color.White,
                            fontSize = fontSize,
                            fontWeight = FontWeight.Black
                        )
                    }
                },
                error = {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(Brush.linearGradient(listOf(Indigo500, Indigo600))),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = initials,
                            color = Color.White,
                            fontSize = fontSize,
                            fontWeight = FontWeight.Black
                        )
                    }
                }
            )
        } else {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Brush.linearGradient(listOf(Indigo500, Indigo600))),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = initials,
                    color = Color.White,
                    fontSize = fontSize,
                    fontWeight = FontWeight.Black
                )
            }
        }
    }
}

/**
 * Modifier for iOS-like micro-animations on press
 */
fun Modifier.scaleOnPress(): Modifier = this.composed {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.94f else 1.0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioLowBouncy,
            stiffness = Spring.StiffnessMediumLow
        ),
        label = "ScaleOnPress"
    )
    this.graphicsLayer {
        scaleX = scale
        scaleY = scale
    }
}

/**
 * Official Brand Logo matching the signature VR Here brand identity:
 * [VR Monogram] | [Here (underlined)] [Business Management Solutions]
 */
@Composable
fun VRLogoView(
    modifier: Modifier = Modifier,
    height: androidx.compose.ui.unit.Dp = 28.dp,
    isDark: Boolean = false,
    onClick: (() -> Unit)? = null
) {
    Row(
        modifier = modifier
            .height(height)
            .then(
                if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier
            ),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp)
    ) {
        // 1. Stylized VR Monogram Icon
        Image(
            painter = painterResource(id = R.drawable.logo),
            contentDescription = "VR Here",
            contentScale = ContentScale.Fit,
            modifier = Modifier.size(height)
        )

        // 2. Subtle Vertical Divider Line with Centered Red Dot
        Box(
            modifier = Modifier
                .height(height * 0.88f)
                .width(6.dp),
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .width(1.dp)
                    .fillMaxHeight()
                    .background(if (isDark) Color.White.copy(alpha = 0.35f) else Color(0xFFCBD5E1))
            )
            Box(
                modifier = Modifier
                    .size(4.5.dp)
                    .background(PrimaryRed, CircleShape)
            )
        }

        // 3. Brand Name & Subtitle
        Column(
            modifier = Modifier.height(height),
            verticalArrangement = Arrangement.SpaceBetween,
            horizontalAlignment = Alignment.Start
        ) {
            // "Here" with its signature red underline
            Column(
                modifier = Modifier.width(IntrinsicSize.Min),
                horizontalAlignment = Alignment.Start
            ) {
                Text(
                    text = "Here",
                    color = PrimaryRed,
                    fontFamily = FontFamily.Serif,
                    fontWeight = FontWeight.Bold,
                    fontSize = (height.value * 0.52f).sp,
                    lineHeight = (height.value * 0.52f).sp,
                    letterSpacing = 0.sp
                )
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(1.4.dp)
                        .background(PrimaryRed)
                )
            }

            // Subtitle: "Business Management Solutions"
            Text(
                text = "Business Management Solutions",
                color = if (isDark) Color.White.copy(alpha = 0.9f) else Color(0xFF1E293B),
                fontWeight = FontWeight.Bold,
                fontSize = (height.value * 0.25f).sp,
                lineHeight = (height.value * 0.28f).sp,
                letterSpacing = 0.15.sp,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

/**
 * Top App Header Bar matching the exact specification:
 * [Toggle] [Logo] ---------------- [Notification Bell] [User Profile Pic] [Logout Button]
 */
@Composable
fun VRHeader(
    title: String = "DASHBOARD",
    showMenu: Boolean = true,
    onMenuClick: (() -> Unit)? = null,
    showBack: Boolean = false,
    onBackClick: (() -> Unit)? = null,
    onLogoClick: (() -> Unit)? = null,
    showNotifications: Boolean = true,
    hasUnreadNotifications: Boolean = false,
    unreadNotificationsCount: Int = 0,
    onNotificationsClick: (() -> Unit)? = null,
    showLogout: Boolean = true,
    onLogoutClick: (() -> Unit)? = null,
    userProfilePhoto: String? = null,
    userName: String = "",
    onProfileClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(Color.White)
            .statusBarsPadding()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(58.dp)
                .padding(horizontal = 14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // LEFT SIDE: Toggle + Official Brand Logo
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (showMenu) {
                    IconButton(
                        onClick = { onMenuClick?.invoke() },
                        modifier = Modifier
                            .size(38.dp)
                            .scaleOnPress()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Menu,
                            contentDescription = "Toggle Menu",
                            tint = Slate700,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                } else if (showBack) {
                    IconButton(
                        onClick = { onBackClick?.invoke() },
                        modifier = Modifier
                            .size(38.dp)
                            .scaleOnPress()
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = Slate700,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }

                // Official Brand Logo (VR emblem + divider with red dot + "Here" + "Business Management Solutions")
                VRLogoView(height = 26.dp, onClick = onLogoClick)
            }

            // RIGHT SIDE: Notification Bell + User Profile Pic + Logout Button
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // 1. Notification Bell
                if (showNotifications) {
                    IconButton(
                        onClick = { onNotificationsClick?.invoke() },
                        modifier = Modifier
                            .size(36.dp)
                            .scaleOnPress()
                    ) {
                        Box(contentAlignment = Alignment.TopEnd) {
                            Icon(
                                imageVector = Icons.Default.Notifications,
                                contentDescription = "Notifications",
                                tint = Slate700,
                                modifier = Modifier.size(22.dp)
                            )
                            if (unreadNotificationsCount > 0 || hasUnreadNotifications) {
                                Surface(
                                    shape = CircleShape,
                                    color = PrimaryRed,
                                    border = BorderStroke(1.5.dp, Color.White),
                                    modifier = Modifier.offset(x = 5.dp, y = (-4).dp)
                                ) {
                                    val badgeText = if (unreadNotificationsCount > 99) "99+" else if (unreadNotificationsCount > 0) "$unreadNotificationsCount" else ""
                                    if (badgeText.isNotEmpty()) {
                                        Text(
                                            text = badgeText,
                                            color = Color.White,
                                            fontSize = 8.5.sp,
                                            fontWeight = FontWeight.Black,
                                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 0.5.dp)
                                        )
                                    } else {
                                        Box(modifier = Modifier.size(7.dp))
                                    }
                                }
                            }
                        }
                    }
                }

                // 2. User Profile Pic (Avatar with photo or initials)
                VRAvatarView(
                    photoUrl = userProfilePhoto,
                    name = userName.ifBlank { "Customer" },
                    size = 32.dp,
                    borderWidth = 1.5.dp,
                    borderColor = Slate200,
                    fontSize = 11.5.sp,
                    onClick = onProfileClick
                )

                // 3. Logout Button
                if (showLogout) {
                    IconButton(
                        onClick = { onLogoutClick?.invoke() },
                        modifier = Modifier
                            .size(36.dp)
                            .scaleOnPress()
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ExitToApp,
                            contentDescription = "Sign Out",
                            tint = Color(0xFFEF4444),
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }
            }
        }
        HorizontalDivider(thickness = 1.dp, color = Slate200)
    }
}

/**
 * Notifications Bottom Sheet matching iOS NotificationsSheet
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationsSheet(
    notifications: List<NotificationResponse>,
    onMarkAsRead: (String) -> Unit,
    onMarkAllAsRead: (() -> Unit)? = null,
    onNotificationClick: ((NotificationResponse) -> Unit)? = null,
    onDismiss: () -> Unit
) {
    val unreadCount = notifications.count { !it.isRead }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = BgLight,
        dragHandle = { BottomSheetDefaults.DragHandle() },
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp)
        ) {
            // Header Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Notifications",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        color = TextDark
                    )
                    if (unreadCount > 0) {
                        Surface(
                            shape = CircleShape,
                            color = PrimaryRed.copy(alpha = 0.1f),
                            border = BorderStroke(1.dp, PrimaryRed.copy(alpha = 0.25f))
                        ) {
                            Text(
                                text = "$unreadCount new",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Black,
                                color = PrimaryRed,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (unreadCount > 0 && onMarkAllAsRead != null) {
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = Color.White,
                            border = BorderStroke(1.dp, BorderLight),
                            modifier = Modifier.clickable { onMarkAllAsRead() }
                        ) {
                            Text(
                                text = "Mark all read",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextDark,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                            )
                        }
                    }

                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier
                            .size(30.dp)
                            .background(BgInput, CircleShape)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Close",
                            tint = TextMuted,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            HorizontalDivider(color = BorderLight)

            if (notifications.isEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(200.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.NotificationsOff,
                        contentDescription = null,
                        tint = TextMuted.copy(alpha = 0.6f),
                        modifier = Modifier.size(36.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "No notifications recorded.",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextMuted
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(notifications) { item ->
                        val dotColor = when (item.type.lowercase()) {
                            "alert", "error", "critical" -> PrimaryRed
                            "warning" -> Amber500
                            "success" -> Emerald500
                            "info" -> Indigo500
                            "order" -> Color(0xFF2563EB)
                            "ticket" -> Color(0xFF7C3AED)
                            "payment" -> Color(0xFF059669)
                            else -> Purple40
                        }

                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (!item.isRead) {
                                        onMarkAsRead(item.id)
                                    }
                                    onNotificationClick?.invoke(item)
                                },
                            shape = RoundedCornerShape(14.dp),
                            color = if (item.isRead) Color.White else Color(0xFFF8FAFC),
                            border = BorderStroke(1.dp, if (item.isRead) BorderLight else Color(0xFFCBD5E1)),
                            shadowElevation = if (item.isRead) 0.5.dp else 2.dp
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
                                        .padding(top = 4.dp)
                                        .size(8.dp)
                                        .background(dotColor, CircleShape)
                                )

                                Column(
                                    modifier = Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = item.title,
                                            fontSize = 13.sp,
                                            fontWeight = if (item.isRead) FontWeight.SemiBold else FontWeight.Black,
                                            color = TextDark
                                        )
                                        if (!item.isRead) {
                                            Box(
                                                modifier = Modifier
                                                    .size(6.dp)
                                                    .background(PrimaryRed, CircleShape)
                                            )
                                        }
                                    }
                                    Text(
                                        text = item.message,
                                        fontSize = 11.sp,
                                        color = TextMuted,
                                        lineHeight = 15.sp
                                    )
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = item.createdAt.take(16).replace("T", " "),
                                            fontSize = 9.sp,
                                            color = TextMuted.copy(alpha = 0.8f)
                                        )
                                        Text(
                                            text = "Open ›",
                                            fontSize = 10.sp,
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
        }
    }
}

/**
 * Dock item model for BMSAppFloatingDock
 */
data class DockItem(
    val id: String,
    val label: String,
    val icon: ImageVector,
    val badgeCount: Int? = null
)

/**
 * Clean Premium Glassmorphic Bottom Navigation Bar with 5 Restored Tabs
 * - Only swipe up gesture opens the Workspace Hub Bottom Sheet
 * - Tab clicks strictly navigate between the 5 primary tabs
 */
@Composable
fun BMSAppBottomNavBar(
    activeTab: String,
    onTabSelected: (String) -> Unit,
    onOpenMenuSheet: () -> Unit,
    modifier: Modifier = Modifier,
    ordersBadgeCount: Int? = null
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .shadow(16.dp, spotColor = Color.Black.copy(alpha = 0.08f), ambientColor = Color.Black.copy(alpha = 0.04f))
            .pointerInput(Unit) {
                var totalDragY = 0f
                detectVerticalDragGestures(
                    onDragStart = { totalDragY = 0f },
                    onVerticalDrag = { change, dragAmount ->
                        change.consume()
                        totalDragY += dragAmount
                    },
                    onDragEnd = {
                        if (totalDragY < -15f) { // Swipe up gesture detected -> opens bottom sheet
                            onOpenMenuSheet()
                        }
                    }
                )
            },
        color = Color.White.copy(alpha = 0.98f),
        border = BorderStroke(1.dp, BorderLight)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Subtle Swipe-Up Indicator Pill Bar at the top of navbar
            Box(
                modifier = Modifier
                    .padding(top = 6.dp, bottom = 2.dp)
                    .width(36.dp)
                    .height(3.5.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(TextMuted.copy(alpha = 0.25f))
            )

            // Restored 5 Navigation Tabs (Strictly click to switch tab)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(58.dp)
                    .padding(horizontal = 4.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Tab 1: Home
                NavBarTabItem(
                    id = "Home",
                    label = "Home",
                    icon = Icons.Default.Home,
                    isSelected = activeTab == "Home",
                    onClick = { onTabSelected("Home") },
                    modifier = Modifier.weight(1f)
                )

                // Tab 2: Services
                NavBarTabItem(
                    id = "Services",
                    label = "Services",
                    icon = Icons.Default.Widgets,
                    isSelected = activeTab == "Services",
                    onClick = { onTabSelected("Services") },
                    modifier = Modifier.weight(1f)
                )

                // Tab 3: Orders
                NavBarTabItem(
                    id = "Orders",
                    label = "Orders",
                    icon = Icons.Default.ShoppingBag,
                    isSelected = activeTab == "Orders",
                    badgeCount = ordersBadgeCount,
                    onClick = { onTabSelected("Orders") },
                    modifier = Modifier.weight(1f)
                )

                // Tab 4: Docs / Vault
                NavBarTabItem(
                    id = "Vault",
                    label = "Docs",
                    icon = Icons.Default.Folder,
                    isSelected = activeTab == "Vault",
                    onClick = { onTabSelected("Vault") },
                    modifier = Modifier.weight(1f)
                )

                // Tab 5: Invoices / Billing
                NavBarTabItem(
                    id = "Invoices",
                    label = "Invoices",
                    icon = Icons.AutoMirrored.Filled.ReceiptLong,
                    isSelected = activeTab == "Invoices" || activeTab == "Billing",
                    onClick = { onTabSelected("Invoices") },
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun NavBarTabItem(
    id: String,
    label: String,
    icon: ImageVector,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    badgeCount: Int? = null
) {
    val scale by animateFloatAsState(
        targetValue = if (isSelected) 1.05f else 1.0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMediumLow
        ),
        label = "TabScale_$id"
    )

    Box(
        modifier = modifier
            .fillMaxHeight()
            .padding(vertical = 2.dp, horizontal = 2.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(
                if (isSelected) PrimaryRed.copy(alpha = 0.08f) else Color.Transparent
            )
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null
            ) {
                onClick()
            }
            .graphicsLayer {
                scaleX = scale
                scaleY = scale
            },
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(contentAlignment = Alignment.TopEnd) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = if (isSelected) PrimaryRed else TextMuted,
                    modifier = Modifier.size(22.dp)
                )
                if (badgeCount != null && badgeCount > 0) {
                    Box(
                        modifier = Modifier
                            .offset(x = 8.dp, y = (-4).dp)
                            .background(PrimaryRed, CircleShape)
                            .border(1.dp, Color.White, CircleShape)
                            .padding(horizontal = 4.dp, vertical = 1.dp)
                    ) {
                        Text(
                            text = if (badgeCount > 99) "99+" else "$badgeCount",
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Black,
                            color = Color.White
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(2.dp))

            Text(
                text = label,
                fontSize = 10.5.sp,
                fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Medium,
                color = if (isSelected) PrimaryRed else TextMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        if (isSelected) {
            Box(
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .width(18.dp)
                    .height(2.5.dp)
                    .background(
                        Brush.horizontalGradient(
                            listOf(PrimaryRed, PrimaryRedLight)
                        ),
                        RoundedCornerShape(bottomStart = 2.dp, bottomEnd = 2.dp)
                    )
            )
        }
    }
}

/**
 * Enhanced Ultra-Premium Bottom Sheet Menu View containing all Workspace Hub / Sidebar elements
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BMSBottomSheetMenuView(
    userName: String,
    activeTab: String,
    profilePhoto: String? = null,
    companyName: String? = null,
    onDismissRequest: () -> Unit,
    onSelectTab: (String) -> Unit,
    onLogout: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismissRequest,
        containerColor = BgLight,
        dragHandle = {
            Box(
                modifier = Modifier
                    .padding(top = 10.dp, bottom = 6.dp)
                    .width(44.dp)
                    .height(4.5.dp)
                    .clip(RoundedCornerShape(3.dp))
                    .background(TextMuted.copy(alpha = 0.35f))
            )
        },
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(bottom = 24.dp)
        ) {
            // Header Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                VRLogoView(height = 26.dp)

                IconButton(
                    onClick = onDismissRequest,
                    modifier = Modifier
                        .size(32.dp)
                        .background(BgInput, CircleShape)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = TextMuted,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            HorizontalDivider(color = BorderLight)

            // Scrollable List of Categorized Module Cards
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                // Profile & Verified Status Header Card
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    color = DarkSlate,
                    shadowElevation = 3.dp
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        VRAvatarView(
                            photoUrl = profilePhoto,
                            name = userName,
                            size = 46.dp,
                            borderWidth = 1.5.dp,
                            borderColor = Color.White.copy(alpha = 0.4f),
                            fontSize = 15.sp
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = userName.ifEmpty { "Customer" },
                                    color = Color.White,
                                    fontSize = 14.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Icon(
                                    imageVector = Icons.Default.CheckCircle,
                                    contentDescription = "Verified",
                                    tint = Emerald500,
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                            Text(
                                text = companyName?.ifBlank { null } ?: "Verified Business Account",
                                color = Slate400,
                                fontSize = 11.5.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        Button(
                            onClick = {
                                onDismissRequest()
                                onLogout()
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed.copy(alpha = 0.25f)),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = "Sign Out",
                                color = Color(0xFFFF8080),
                                fontSize = 11.5.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                // Section 1: Core Operations
                HubSectionHeader(title = "CORE OPERATIONS")

                // 1. Dashboard Overview
                BMSModuleHubCard(
                    icon = Icons.Default.Dashboard,
                    iconTint = Indigo500,
                    iconBg = Indigo500.copy(alpha = 0.10f),
                    title = "Dashboard Overview",
                    description = "Live Business Summary, Revenue & Active Orders",
                    subChips = listOf("Live Overview", "Recent Orders", "Quick Actions"),
                    isSelected = activeTab == "Home",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Home")
                    }
                )

                // 2. Services Catalog
                BMSModuleHubCard(
                    icon = Icons.Default.Work,
                    iconTint = PrimaryRed,
                    iconBg = PrimaryRed.copy(alpha = 0.10f),
                    title = "Services Catalog",
                    description = "50+ Legal, MCA, GST, Tax & Trademark Packages",
                    subChips = listOf("Business Setup", "Tax & GST", "Trademark", "Licenses"),
                    isSelected = activeTab == "Services",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Services")
                    }
                )

                // 3. My Orders & Requirements
                BMSModuleHubCard(
                    icon = Icons.Default.ShoppingBag,
                    iconTint = Color(0xFFEA580C),
                    iconBg = Color(0xFFEA580C).copy(alpha = 0.10f),
                    title = "My Orders & Workspace",
                    description = "Document Requirement Uploads & Milestone Timeline",
                    subChips = listOf("All Orders", "Requirements KYC", "Live Timeline"),
                    isSelected = activeTab == "Orders",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Orders")
                    }
                )

                // Section 2: Financials & Documents
                HubSectionHeader(title = "FINANCIALS & VAULT")

                // 4. Refer & Earn
                BMSModuleHubCard(
                    icon = Icons.Default.CardGiftcard,
                    iconTint = Color(0xFFDC2626),
                    iconBg = Color(0xFFDC2626).copy(alpha = 0.10f),
                    title = "Refer & Earn (₹500 Cash)",
                    description = "Refer business colleagues & get instant UPI payout",
                    subChips = listOf("Share Link", "Submit Lead", "UPI Payout"),
                    isSelected = activeTab == "Referrals",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Referrals")
                    }
                )

                // 5. Invoices & Receipts
                BMSModuleHubCard(
                    icon = Icons.AutoMirrored.Filled.ReceiptLong,
                    iconTint = Emerald500,
                    iconBg = Emerald500.copy(alpha = 0.10f),
                    title = "Invoices & GST Receipts",
                    description = "Digital Tax Invoices, GST Breakdown & Downloads",
                    subChips = listOf("Tax Invoices", "Paid Receipts", "GST Summary"),
                    isSelected = activeTab == "Invoices",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Invoices")
                    }
                )

                // 6. Vault Documents
                BMSModuleHubCard(
                    icon = Icons.Default.Folder,
                    iconTint = Color(0xFF8B5CF6),
                    iconBg = Color(0xFF8B5CF6).copy(alpha = 0.10f),
                    title = "Vault Documents",
                    description = "8 Master KYC identity proofs & Deliverables",
                    subChips = listOf("Master KYC (8)", "Deliverables", "Certificates"),
                    isSelected = activeTab == "Vault",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Vault")
                    }
                )

                // 7. Bookkeeping Suite
                BMSModuleHubCard(
                    icon = Icons.Default.Book,
                    iconTint = Color(0xFF0284C7),
                    iconBg = Color(0xFF0284C7).copy(alpha = 0.10f),
                    title = "Bookkeeping Suite",
                    description = "Sales, Purchases, Expenses, Bank Accounts & Payroll",
                    subChips = listOf("Sales", "Purchases", "Expenses", "Bank", "Parties", "Payroll", "Reports"),
                    isSelected = activeTab == "Bookkeeping",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Bookkeeping")
                    }
                )

                // Section 3: Assistance & Profile
                HubSectionHeader(title = "ASSISTANCE & PROFILE")

                // 8. Help & CA Support
                BMSModuleHubCard(
                    icon = Icons.Default.HeadsetMic,
                    iconTint = Color(0xFF0D9488),
                    iconBg = Color(0xFF0D9488).copy(alpha = 0.10f),
                    title = "Help & CA Advisory",
                    description = "Dedicated Chartered Accountant Support & Tickets",
                    subChips = listOf("WhatsApp Chat", "Direct Call", "Support Tickets"),
                    isSelected = activeTab == "Support",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Support")
                    }
                )

                // 9. My Profile & Account
                BMSModuleHubCard(
                    icon = Icons.Default.Person,
                    iconTint = Color(0xFF475569),
                    iconBg = Color(0xFF475569).copy(alpha = 0.10f),
                    title = "My Profile & Settings",
                    description = "Account Info, Phone Number, Security & Privacy",
                    subChips = listOf("Profile Info", "Security", "Helpline"),
                    isSelected = activeTab == "Account",
                    onCardClick = {
                        onDismissRequest()
                        onSelectTab("Account")
                    }
                )
            }
        }
    }
}

@Composable
private fun HubSectionHeader(title: String) {
    Text(
        text = title,
        fontSize = 11.sp,
        fontWeight = FontWeight.Black,
        color = TextMuted,
        letterSpacing = 0.8.sp,
        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
    )
}

@Composable
private fun BMSModuleHubCard(
    icon: ImageVector,
    iconTint: Color,
    iconBg: Color,
    title: String,
    description: String,
    subChips: List<String>,
    isSelected: Boolean,
    onCardClick: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCardClick() },
        shape = RoundedCornerShape(16.dp),
        color = Color.White,
        border = BorderStroke(1.dp, if (isSelected) iconTint.copy(alpha = 0.5f) else BorderLight),
        shadowElevation = if (isSelected) 3.dp else 1.dp
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(iconBg),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = iconTint,
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    Column {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = title,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSelected) iconTint else TextDark
                            )
                            if (isSelected) {
                                Surface(
                                    color = iconTint.copy(alpha = 0.12f),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = "ACTIVE",
                                        fontSize = 8.5.sp,
                                        fontWeight = FontWeight.Black,
                                        color = iconTint,
                                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp)
                                    )
                                }
                            }
                        }
                        Text(
                            text = description,
                            fontSize = 11.5.sp,
                            color = TextMuted,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    tint = if (isSelected) iconTint else TextMuted.copy(alpha = 0.5f),
                    modifier = Modifier.size(16.dp)
                )
            }

            if (subChips.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    subChips.forEach { chipText ->
                        Surface(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .clickable { onCardClick() },
                            color = BgInput,
                            shape = RoundedCornerShape(6.dp),
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Text(
                                text = chipText,
                                fontSize = 10.5.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = TextDark.copy(alpha = 0.85f),
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * Reusable Glassmorphic Card Container matching iOS GlassCardModifier
 */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    shape: androidx.compose.ui.graphics.Shape = RoundedCornerShape(16.dp),
    backgroundColor: Color = Color.White,
    borderColor: Color = BorderLight,
    elevation: androidx.compose.ui.unit.Dp = 2.dp,
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = shape,
        color = backgroundColor,
        border = BorderStroke(1.dp, borderColor),
        shadowElevation = elevation
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            content = content
        )
    }
}

/**
 * 1:1 Floating Dark Pill Navigation Bar matching iOS & Web
 */
@Composable
fun BMSAppFloatingDock(
    activeTab: String,
    dockItems: List<DockItem>,
    onTabSelected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(horizontal = 16.dp, vertical = 6.dp),
        contentAlignment = Alignment.Center
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .height(58.dp)
                .shadow(12.dp, RoundedCornerShape(24.dp), spotColor = Color(0x60000000)),
            shape = RoundedCornerShape(24.dp),
            color = Color(0xFF0F172A),
            border = BorderStroke(1.dp, Color(0xFF334155))
        ) {
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 4.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically
            ) {
                dockItems.forEach { item ->
                    val isSelected = activeTab == item.id
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .clip(RoundedCornerShape(18.dp))
                            .background(
                                if (isSelected) Color(0xFFDC2626) else Color.Transparent
                            )
                            .clickable { onTabSelected(item.id) },
                        contentAlignment = Alignment.Center
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center,
                            modifier = Modifier.padding(vertical = 2.dp)
                        ) {
                            Box(contentAlignment = Alignment.TopEnd) {
                                Icon(
                                    imageVector = item.icon,
                                    contentDescription = item.label,
                                    tint = if (isSelected) Color.White else Color(0xFF94A3B8),
                                    modifier = Modifier.size(19.dp)
                                )
                                if (item.badgeCount != null && item.badgeCount > 0) {
                                    Box(
                                        modifier = Modifier
                                            .offset(x = 8.dp, y = (-3).dp)
                                            .background(Color(0xFFEF4444), CircleShape)
                                            .border(1.dp, Color(0xFF0F172A), CircleShape)
                                            .padding(horizontal = 4.dp, vertical = 0.5.dp)
                                    ) {
                                        Text(
                                            text = if (item.badgeCount > 99) "99+" else "${item.badgeCount}",
                                            color = Color.White,
                                            fontSize = 7.5.sp,
                                            fontWeight = FontWeight.Black
                                        )
                                    }
                                }
                            }
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = item.label,
                                fontSize = 9.5.sp,
                                fontWeight = if (isSelected) FontWeight.Black else FontWeight.Medium,
                                color = if (isSelected) Color.White else Color(0xFF94A3B8),
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * 1:1 Speed-dial Floating Action Button matching Web & iOS QuickActionFAB
 */
@Composable
fun BMSQuickActionFAB(
    onNewOrder: () -> Unit,
    onNewTodo: () -> Unit,
    modifier: Modifier = Modifier
) {
    var isOpen by remember { mutableStateOf(false) }
    val rotation by animateFloatAsState(
        targetValue = if (isOpen) 45f else 0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMediumLow
        ),
        label = "FABRotation"
    )

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.End,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        AnimatedVisibility(
            visible = isOpen,
            enter = fadeIn() + slideInVertically { it / 2 },
            exit = fadeOut() + slideOutVertically { it / 2 }
        ) {
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                // 1. New Order Action
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .clickable {
                            isOpen = false
                            onNewOrder()
                        }
                        .padding(horizontal = 4.dp, vertical = 2.dp)
                ) {
                    Surface(
                        color = Color(0xDD0F172A),
                        shape = RoundedCornerShape(8.dp),
                        shadowElevation = 6.dp
                    ) {
                        Text(
                            text = "New Order",
                            color = Color.White,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(46.dp)
                            .shadow(8.dp, CircleShape, spotColor = Color(0xFF10B981))
                            .background(Color(0xFF10B981), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.AddShoppingCart,
                            contentDescription = "New Order",
                            tint = Color.White,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                // 2. New Task Action
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .clickable {
                            isOpen = false
                            onNewTodo()
                        }
                        .padding(horizontal = 4.dp, vertical = 2.dp)
                ) {
                    Surface(
                        color = Color(0xDD0F172A),
                        shape = RoundedCornerShape(8.dp),
                        shadowElevation = 6.dp
                    ) {
                        Text(
                            text = "New Task",
                            color = Color.White,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(46.dp)
                            .shadow(8.dp, CircleShape, spotColor = Color(0xFF2563EB))
                            .background(Color(0xFF2563EB), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "New Task",
                            tint = Color.White,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
        }

        // Main Toggle FAB
        Box(
            modifier = Modifier
                .size(56.dp)
                .shadow(12.dp, CircleShape, spotColor = Color(0xFF4F46E5))
                .clip(CircleShape)
                .background(
                    if (isOpen) Color(0xFF1E293B) else Color(0xFF4F46E5),
                    CircleShape
                )
                .clickable { isOpen = !isOpen },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Add,
                contentDescription = "Quick Actions",
                tint = Color.White,
                modifier = Modifier
                    .size(26.dp)
                    .graphicsLayer { rotationZ = rotation }
            )
        }
    }
}

/**
 * 1:1 BMSSidebarItem and BMSAppSidebar matching iOS & Web
 */
data class BMSSidebarItem(
    val id: String,
    val label: String,
    val icon: ImageVector,
    val category: String? = null
)

@Composable
fun BMSAppSidebar(
    userName: String,
    roleName: String = "System Administrator",
    menuItems: List<BMSSidebarItem>,
    activeTab: String,
    onTabSelected: (String) -> Unit,
    onLogout: () -> Unit,
    onClose: () -> Unit
) {
    ModalDrawerSheet(
        drawerContainerColor = Color(0xFF060A18),
        drawerShape = RoundedCornerShape(topEnd = 24.dp, bottomEnd = 24.dp),
        modifier = Modifier.width(300.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(vertical = 16.dp)
        ) {
            // User Header Card
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .background(Color.White.copy(alpha = 0.06f), RoundedCornerShape(16.dp))
                    .border(1.dp, Color.White.copy(alpha = 0.08f), RoundedCornerShape(16.dp))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .background(
                            Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFF3B82F6))),
                            CircleShape
                        )
                        .border(1.5.dp, Color.White.copy(alpha = 0.3f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = userName.take(1).uppercase().ifEmpty { "A" },
                        color = Color.White,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Black
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = userName.ifEmpty { "Administrator" },
                        color = Color.White,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = roleName,
                        color = Color(0xFFA0AFC8),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                IconButton(
                    onClick = onClose,
                    modifier = Modifier.size(28.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = Color.White.copy(alpha = 0.08f))

            // Navigation List
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                menuItems.forEach { item ->
                    val isSelected = activeTab == item.id
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(
                                if (isSelected) {
                                    Brush.horizontalGradient(listOf(Color(0xFF4F46E5), Color(0xFF2563EB)))
                                } else {
                                    Brush.horizontalGradient(listOf(Color.Transparent, Color.Transparent))
                                }
                            )
                            .clickable {
                                onTabSelected(item.id)
                                onClose()
                            }
                            .padding(horizontal = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            imageVector = item.icon,
                            contentDescription = item.label,
                            tint = if (isSelected) Color.White else Color(0xFFA0AFCD),
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = item.label,
                            color = if (isSelected) Color.White else Color(0xFFCBD5E1),
                            fontSize = 13.sp,
                            fontWeight = if (isSelected) FontWeight.Black else FontWeight.Medium,
                            modifier = Modifier.weight(1f)
                        )
                        if (isSelected) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(Color(0xFF38BDF8), CircleShape)
                            )
                        }
                    }
                }
            }

            HorizontalDivider(color = Color.White.copy(alpha = 0.08f))
            Spacer(modifier = Modifier.height(12.dp))

            // Sign Out Button
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .background(Color(0x22EF4444), RoundedCornerShape(12.dp))
                    .border(1.dp, Color(0x44EF4444), RoundedCornerShape(12.dp))
                    .clickable {
                        onClose()
                        onLogout()
                    }
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ExitToApp,
                    contentDescription = "Sign Out",
                    tint = Color(0xFFFF6464),
                    modifier = Modifier.size(18.dp)
                )
                Text(
                    text = "Sign Out",
                    color = Color(0xFFFF6464),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
