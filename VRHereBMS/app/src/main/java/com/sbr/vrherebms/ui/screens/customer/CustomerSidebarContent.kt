package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun CustomerSidebarContent(
    userName: String,
    activeTab: String,
    onTabSelected: (String) -> Unit,
    onLogout: () -> Unit,
    onCloseDrawer: () -> Unit
) {
    val darkSlate = Color(0xFF0F172A)
    val lightBorder = Color.White.copy(alpha = 0.08f)

    // Animation States for Premium Stagger Spring slide-in transitions
    val avatarAnimatable = remember { Animatable(0f) }
    val headerAnimatable = remember { Animatable(0f) }
    
    val menuItems = listOf(
        Triple("Home", Icons.Default.Dashboard, "Dashboard"),
        Triple("Services", Icons.Default.Work, "Services Catalog"),
        Triple("Orders", Icons.Default.ShoppingBag, "My Orders"),
        Triple("Invoices", Icons.Default.ReceiptLong, "Invoices"),
        Triple("Vault", Icons.Default.Folder, "Vault Documents"),
        Triple("Bookkeeping", Icons.Default.Book, "Bookkeeping"),
        Triple("Support", Icons.Default.HeadsetMic, "Help & Support"),
        Triple("Account", Icons.Default.Person, "My Profile")
    )
    
    val itemAnimatables = remember { List(menuItems.size) { Animatable(0f) } }
    val logoutAnimatable = remember { Animatable(0f) }

    LaunchedEffect(Unit) {
        // Animate brand header & profile card in first
        launch {
            headerAnimatable.animateTo(
                1f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessLow
                )
            )
        }
        launch {
            avatarAnimatable.animateTo(
                1f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessLow
                )
            )
        }
        // Stagger list items sequentially
        menuItems.forEachIndexed { index, _ ->
            launch {
                delay(60L + index * 40L)
                itemAnimatables[index].animateTo(
                    1f,
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                )
            }
        }
        // Finally, animate logout footer
        launch {
            delay(100L + menuItems.size * 40L)
            logoutAnimatable.animateTo(
                1f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioMediumBouncy,
                    stiffness = Spring.StiffnessMedium
                )
            )
        }
    }

    Column(
        modifier = Modifier
            .fillMaxHeight()
            .width(300.dp)
            .background(darkSlate)
            .statusBarsPadding()
            .navigationBarsPadding()
    ) {
        // 1. Sidebar Header (Brand Logo + Close Button)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .graphicsLayer {
                    alpha = headerAnimatable.value
                    translationX = (1f - headerAnimatable.value) * -30.dp.toPx()
                }
                .padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .background(Color(0xFF6366F1), RoundedCornerShape(10.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "VR",
                        color = Color.White,
                        fontWeight = FontWeight.Black,
                        fontSize = 14.sp
                    )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = "VRHERE BMS",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = (-0.3).sp
                )
            }

            IconButton(
                onClick = onCloseDrawer,
                modifier = Modifier
                    .size(36.dp)
                    .background(Color.White.copy(alpha = 0.05f), CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Close Menu",
                    tint = Color.White.copy(alpha = 0.8f),
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        HorizontalDivider(color = lightBorder)

        // 2. Profile Details Section (Premium glassmorphism wrapper + glow avatar)
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .graphicsLayer {
                    alpha = avatarAnimatable.value
                    scaleX = 0.85f + 0.15f * avatarAnimatable.value
                    scaleY = 0.85f + 0.15f * avatarAnimatable.value
                }
                .padding(horizontal = 16.dp, vertical = 20.dp)
                .background(Color.White.copy(alpha = 0.02f), RoundedCornerShape(20.dp))
                .border(1.dp, Color.White.copy(alpha = 0.04f), RoundedCornerShape(20.dp))
                .padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                val initials = userName.split(" ")
                    .mapNotNull { it.firstOrNull()?.uppercase() }
                    .take(2)
                    .joinToString("")

                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(
                            Brush.linearGradient(
                                listOf(Color(0xFF6366F1), Color(0xFF8B5CF6))
                            ),
                            CircleShape
                        )
                        .border(2.dp, Color.White.copy(alpha = 0.2f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = initials.ifEmpty { "C" },
                        color = Color.White,
                        fontWeight = FontWeight.Black,
                        fontSize = 16.sp
                    )
                }

                Spacer(modifier = Modifier.width(14.dp))

                Column {
                    Text(
                        text = userName,
                        color = Color.White,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "Customer Account",
                        color = Color(0xFF94A3B8),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }

        HorizontalDivider(color = lightBorder)

        // 3. Navigation List
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            menuItems.forEachIndexed { index, (tabId, icon, label) ->
                val isSelected = activeTab == tabId
                val animProgress = itemAnimatables[index].value

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .graphicsLayer {
                            alpha = animProgress
                            translationX = (1f - animProgress) * -40.dp.toPx()
                        }
                        .clip(RoundedCornerShape(12.dp))
                        .background(
                            if (isSelected) Color(0xFF6366F1).copy(alpha = 0.15f) else Color.Transparent
                        )
                        .scaleOnPress()
                        .clickable {
                            onTabSelected(tabId)
                            onCloseDrawer()
                        }
                        .padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = label,
                        tint = if (isSelected) Color(0xFF818CF8) else Color(0xFF94A3B8),
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(16.dp))
                    Text(
                        text = label,
                        color = if (isSelected) Color.White else Color(0xFF94A3B8),
                        fontSize = 14.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                    )
                }
            }
        }

        HorizontalDivider(color = lightBorder)

        // 4. Logout Action Footer
        val footerProgress = logoutAnimatable.value
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .graphicsLayer {
                    alpha = footerProgress
                    translationY = (1f - footerProgress) * 20.dp.toPx()
                }
                .padding(16.dp)
                .clip(RoundedCornerShape(12.dp))
                .scaleOnPress()
                .clickable { onLogout() }
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.ExitToApp,
                contentDescription = "Logout",
                tint = Color(0xFFEF4444),
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Text(
                text = "Sign Out",
                color = Color(0xFFEF4444),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
