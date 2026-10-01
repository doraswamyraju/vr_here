package com.sbr.vrherebms.ui.screens.customer.bookkeeping.components

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.PartyDto

@Composable
fun PartyItemCard(
    party: PartyDto,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clickable { onEdit() },
        shape = RoundedCornerShape(16.dp),
        color = Color.White,
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        shadowElevation = 1.dp
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // Header Row: Name + Party Type Pill
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = party.name,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Black,
                    color = textDark,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                Surface(
                    shape = RoundedCornerShape(20.dp),
                    color = when (party.partyType) {
                        "Customer" -> Color(0xFFEEF2FF)
                        "Vendor" -> Color(0xFFECFDF5)
                        else -> Color(0xFFFFFBEB)
                    }
                ) {
                    Text(
                        text = party.partyType.uppercase(),
                        fontSize = 9.5.sp,
                        fontWeight = FontWeight.Black,
                        color = when (party.partyType) {
                            "Customer" -> primaryIndigo
                            "Vendor" -> Color(0xFF059669)
                            else -> Color(0xFFD97706)
                        },
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }

            if (party.tradeName.isNotBlank() && party.tradeName != party.name) {
                Text(
                    text = "Trade: ${party.tradeName}",
                    fontSize = 11.5.sp,
                    color = textMuted,
                    fontWeight = FontWeight.Medium
                )
            }

            // GSTIN and PAN line
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (party.gstin.isNotBlank()) {
                    Text(
                        text = "GSTIN: ${party.gstin}",
                        fontSize = 11.sp,
                        color = textMuted,
                        fontWeight = FontWeight.Bold
                    )
                }
                if (party.pan.isNotBlank()) {
                    Text(
                        text = "PAN: ${party.pan}",
                        fontSize = 11.sp,
                        color = textMuted
                    )
                }
            }

            // Billing address snippet
            if (party.billingAddress.isNotBlank()) {
                Text(
                    text = "${party.billingAddress}, ${party.state}",
                    fontSize = 11.sp,
                    color = textMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))

            // Action Row: Quick Call, Quick WhatsApp, Quick Email, Delete
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Call Button
                    if (party.phone.isNotBlank()) {
                        IconButton(
                            onClick = {
                                try {
                                    val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:${party.phone}"))
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Dialer unavailable", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier
                                .size(30.dp)
                                .background(Color(0xFFEEF2FF), CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Phone,
                                contentDescription = "Call",
                                tint = primaryIndigo,
                                modifier = Modifier.size(15.dp)
                            )
                        }

                        // WhatsApp Button
                        IconButton(
                            onClick = {
                                try {
                                    val cleanPhone = party.phone.replace(Regex("[^0-9]"), "")
                                    val formattedPhone = if (cleanPhone.length == 10) "91$cleanPhone" else cleanPhone
                                    val url = "https://wa.me/$formattedPhone"
                                    val i = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                    context.startActivity(i)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "WhatsApp not installed", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier
                                .size(30.dp)
                                .background(Color(0xFFDCFCE7), CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Chat,
                                contentDescription = "WhatsApp",
                                tint = Color(0xFF16A34A),
                                modifier = Modifier.size(15.dp)
                            )
                        }
                    }

                    // Email Button
                    if (party.email.isNotBlank()) {
                        IconButton(
                            onClick = {
                                try {
                                    val intent = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:${party.email}"))
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Email client unavailable", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier
                                .size(30.dp)
                                .background(Color(0xFFF1F5F9), CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Email,
                                contentDescription = "Email",
                                tint = textMuted,
                                modifier = Modifier.size(15.dp)
                            )
                        }
                    }

                    // Save to Phone Contacts Button
                    if (party.name.isNotBlank() || party.phone.isNotBlank()) {
                        IconButton(
                            onClick = {
                                try {
                                    val intent = Intent(android.provider.ContactsContract.Intents.Insert.ACTION).apply {
                                        type = android.provider.ContactsContract.RawContacts.CONTENT_TYPE
                                        putExtra(android.provider.ContactsContract.Intents.Insert.NAME, party.name)
                                        if (party.phone.isNotBlank()) {
                                            putExtra(android.provider.ContactsContract.Intents.Insert.PHONE, party.phone)
                                            putExtra(android.provider.ContactsContract.Intents.Insert.PHONE_TYPE, android.provider.ContactsContract.CommonDataKinds.Phone.TYPE_WORK)
                                        }
                                        if (party.email.isNotBlank()) {
                                            putExtra(android.provider.ContactsContract.Intents.Insert.EMAIL, party.email)
                                            putExtra(android.provider.ContactsContract.Intents.Insert.EMAIL_TYPE, android.provider.ContactsContract.CommonDataKinds.Email.TYPE_WORK)
                                        }
                                        if (party.tradeName.isNotBlank() || party.partyType.isNotBlank()) {
                                            putExtra(android.provider.ContactsContract.Intents.Insert.COMPANY, party.tradeName.ifBlank { party.name })
                                            putExtra(android.provider.ContactsContract.Intents.Insert.JOB_TITLE, "${party.partyType} (VR HERE)")
                                        }
                                        if (party.billingAddress.isNotBlank()) {
                                            putExtra(android.provider.ContactsContract.Intents.Insert.POSTAL, "${party.billingAddress}, ${party.state} ${party.pincode}".trim().trim(','))
                                        }
                                    }
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Cannot open contacts app: ${e.message}", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier
                                .size(30.dp)
                                .background(Color(0xFFFEF3C7), CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.PersonAddAlt1,
                                contentDescription = "Save to Phone Contacts",
                                tint = Color(0xFFD97706),
                                modifier = Modifier.size(15.dp)
                            )
                        }
                    }
                }

                // Delete Button
                IconButton(
                    onClick = onDelete,
                    modifier = Modifier
                        .size(30.dp)
                        .background(Color(0xFFFEE2E2), CircleShape)
                ) {
                    Icon(
                        imageVector = Icons.Default.DeleteOutline,
                        contentDescription = "Delete",
                        tint = Color(0xFFDC2626),
                        modifier = Modifier.size(15.dp)
                    )
                }
            }
        }
    }
}
