package com.sbr.vrherebms.ui.components

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
 * Official Brand Logo from res/drawable/logo.png
 */
@Composable
fun VRLogoView(
    modifier: Modifier = Modifier,
    height: androidx.compose.ui.unit.Dp = 30.dp
) {
    Image(
        painter = painterResource(id = R.drawable.logo),
        contentDescription = "VR HERE Business Management Solutions",
        contentScale = ContentScale.Fit,
        modifier = modifier.height(height)
    )
}

/**
 * Top App Header Bar matching Web / iOS VRHeader
 */
@Composable
fun VRHeader(
    title: String = "DASHBOARD",
    showMenu: Boolean = false,
    onMenuClick: (() -> Unit)? = null,
    showBack: Boolean = false,
    onBackClick: (() -> Unit)? = null,
    showNotifications: Boolean = false,
    hasUnreadNotifications: Boolean = false,
    onNotificationsClick: (() -> Unit)? = null,
    showLogout: Boolean = false,
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
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .height(58.dp)
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Left Action Buttons (Menu / Back)
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (showMenu) {
                    IconButton(
                        onClick = { onMenuClick?.invoke() },
                        modifier = Modifier.size(36.dp).scaleOnPress()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Menu,
                            contentDescription = "Menu",
                            tint = TextDark,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }
                if (showBack) {
                    IconButton(
                        onClick = { onBackClick?.invoke() },
                        modifier = Modifier.size(36.dp).scaleOnPress()
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = TextDark,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }
            }

            // Center: Official Brand Logo
            VRLogoView(height = 30.dp)

            // Right Action Buttons (Notifications + Avatar / SignOut)
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (showNotifications) {
                    IconButton(
                        onClick = { onNotificationsClick?.invoke() },
                        modifier = Modifier.size(36.dp).scaleOnPress()
                    ) {
                        Box(contentAlignment = Alignment.TopEnd) {
                            Icon(
                                imageVector = Icons.Default.Notifications,
                                contentDescription = "Notifications",
                                tint = TextDark,
                                modifier = Modifier.size(22.dp)
                            )
                            if (hasUnreadNotifications) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .background(PrimaryRed, CircleShape)
                                        .border(1.5.dp, Color.White, CircleShape)
                                        .offset(x = 1.dp, y = (-1).dp)
                                )
                            }
                        }
                    }
                }

                if (userName.isNotBlank() || !userProfilePhoto.isNullOrBlank()) {
                    VRAvatarView(
                        photoUrl = userProfilePhoto,
                        name = userName,
                        size = 34.dp,
                        borderWidth = 1.5.dp,
                        borderColor = BorderLight,
                        fontSize = 12.sp,
                        onClick = onProfileClick
                    )
                } else if (showLogout) {
                    IconButton(
                        onClick = { onLogoutClick?.invoke() },
                        modifier = Modifier.size(36.dp).scaleOnPress()
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ExitToApp,
                            contentDescription = "Sign Out",
                            tint = PrimaryRed,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
        }
        HorizontalDivider(thickness = 1.dp, color = BorderLight)
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
    onDismiss: () -> Unit
) {
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
                Text(
                    text = "Notifications",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = TextDark
                )
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
                            else -> Purple40
                        }

                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onMarkAsRead(item.id) },
                            shape = RoundedCornerShape(14.dp),
                            color = Color.White,
                            border = BorderStroke(1.dp, BorderLight),
                            shadowElevation = 1.dp
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
                                    Text(
                                        text = item.title,
                                        fontSize = 13.sp,
                                        fontWeight = if (item.isRead) FontWeight.SemiBold else FontWeight.Bold,
                                        color = TextDark
                                    )
                                    Text(
                                        text = item.message,
                                        fontSize = 11.sp,
                                        color = TextMuted,
                                        lineHeight = 15.sp
                                    )
                                    Text(
                                        text = item.createdAt ?: "",
                                        fontSize = 9.sp,
                                        color = TextMuted.copy(alpha = 0.8f)
                                    )
                                }

                                if (!item.isRead) {
                                    Box(
                                        modifier = Modifier
                                            .size(6.dp)
                                            .background(Indigo500, CircleShape)
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

                // Tab 5: Account
                NavBarTabItem(
                    id = "Account",
                    label = "Account",
                    icon = Icons.Default.Person,
                    isSelected = activeTab == "Account",
                    onClick = { onTabSelected("Account") },
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
                    .padding(horizontal = 20.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    VRLogoView(height = 28.dp)

                    Column {
                        Text(
                            text = "Workspace Hub",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Black,
                            color = TextDark
                        )
                        Text(
                            text = "All Business Modules & Tools",
                            fontSize = 11.5.sp,
                            fontWeight = FontWeight.Medium,
                            color = TextMuted
                        )
                    }
                }

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
                        modifier = Modifier.size(18.dp)
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
