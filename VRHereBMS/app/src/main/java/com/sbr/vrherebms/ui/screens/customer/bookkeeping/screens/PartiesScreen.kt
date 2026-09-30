package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apartment
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.PartyDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BookkeepingKPICard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.PartyItemCard

fun LazyListScope.partiesScreen(
    parties: List<PartyDto>,
    selectedTypeFilter: String, // "All", "Customer", "Vendor"
    searchQuery: String,
    onTypeFilterChange: (String) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onAddParty: () -> Unit,
    onEditParty: (PartyDto) -> Unit,
    onDeleteParty: (PartyDto) -> Unit
) {
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val customersCount = parties.count { it.partyType.equals("Customer", ignoreCase = true) || it.partyType.equals("Both", ignoreCase = true) }
    val vendorsCount = parties.count { it.partyType.equals("Vendor", ignoreCase = true) || it.partyType.equals("Both", ignoreCase = true) }

    // 1. KPI Summaries
    item {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            BookkeepingKPICard(
                title = "Total Customers",
                value = "$customersCount Parties",
                subtitle = "Active Clients & Buyers",
                icon = Icons.Default.Person,
                accentColor = primaryIndigo,
                modifier = Modifier.weight(1f)
            )
            BookkeepingKPICard(
                title = "Total Vendors",
                value = "$vendorsCount Vendors",
                subtitle = "Suppliers & Contractors",
                icon = Icons.Default.Apartment,
                accentColor = Color(0xFF059669),
                modifier = Modifier.weight(1f)
            )
        }
    }

    // 2. Search & Add Party Bar
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchQueryChange,
                placeholder = { Text("Search party / GSTIN...", fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = textMuted, modifier = Modifier.size(18.dp)) },
                modifier = Modifier.weight(1f).height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    unfocusedContainerColor = Color.White,
                    focusedContainerColor = Color.White
                ),
                singleLine = true
            )

            Button(
                onClick = onAddParty,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                modifier = Modifier.height(48.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Add Party", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
    }

    // 3. Type Filters Bar
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("All", "Customer", "Vendor").forEach { t ->
                val isSel = selectedTypeFilter.equals(t, ignoreCase = true)
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isSel) primaryIndigo else Color.White,
                    border = BorderStroke(1.dp, if (isSel) primaryIndigo else Color(0xFFE2E8F0)),
                    modifier = Modifier.clickable { onTypeFilterChange(t) }
                ) {
                    Text(
                        text = t,
                        fontSize = 11.sp,
                        fontWeight = if (isSel) FontWeight.Black else FontWeight.Bold,
                        color = if (isSel) Color.White else textDark,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }
        }
    }

    // 4. Parties List
    val filtered = parties.filter { p ->
        val typeMatch = selectedTypeFilter.equals("All", ignoreCase = true) ||
            p.partyType.equals(selectedTypeFilter, ignoreCase = true) ||
            p.partyType.equals("Both", ignoreCase = true)
        val searchMatch = searchQuery.isBlank() ||
            p.name.contains(searchQuery, ignoreCase = true) ||
            p.tradeName.contains(searchQuery, ignoreCase = true) ||
            p.gstin.contains(searchQuery, ignoreCase = true) ||
            p.phone.contains(searchQuery, ignoreCase = true)
        typeMatch && searchMatch
    }

    if (filtered.isEmpty()) {
        item {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = Color.White,
                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Icon(Icons.Default.Apartment, contentDescription = null, tint = textMuted, modifier = Modifier.size(32.dp))
                    Text("No Parties Registered", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = textDark)
                    Text("Add your customers and suppliers to auto-fill invoices.", fontSize = 11.sp, color = textMuted)
                }
            }
        }
    } else {
        items(filtered) { p ->
            PartyItemCard(
                party = p,
                onEdit = { onEditParty(p) },
                onDelete = { onDeleteParty(p) }
            )
        }
    }
}
