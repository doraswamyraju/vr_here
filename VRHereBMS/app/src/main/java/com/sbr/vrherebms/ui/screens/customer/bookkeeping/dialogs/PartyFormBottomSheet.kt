package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.ContactsContract
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContactPhone
import androidx.compose.material.icons.filled.PersonAddAlt1
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.PartyDto

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PartyFormBottomSheet(
    existingParty: PartyDto? = null,
    onDismiss: () -> Unit,
    onSubmit: (PartyDto) -> Unit
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    var partyType by remember { mutableStateOf(existingParty?.partyType ?: "Customer") }
    var name by remember { mutableStateOf(existingParty?.name ?: "") }
    var tradeName by remember { mutableStateOf(existingParty?.tradeName ?: "") }
    var gstin by remember { mutableStateOf(existingParty?.gstin ?: "") }
    var pan by remember { mutableStateOf(existingParty?.pan ?: "") }
    var phone by remember { mutableStateOf(existingParty?.phone ?: "") }
    var email by remember { mutableStateOf(existingParty?.email ?: "") }
    var billingAddress by remember { mutableStateOf(existingParty?.billingAddress ?: "") }
    var state by remember { mutableStateOf(existingParty?.state ?: "Andhra Pradesh") }
    var pincode by remember { mutableStateOf(existingParty?.pincode ?: "") }

    // Native Contact Picker Activity Launcher
    val contactPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickContact()
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                val cursor = context.contentResolver.query(uri, null, null, null, null)
                cursor?.use { c ->
                    if (c.moveToFirst()) {
                        val idIndex = c.getColumnIndex(ContactsContract.Contacts._ID)
                        val nameIndex = c.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME)
                        val hasPhoneIndex = c.getColumnIndex(ContactsContract.Contacts.HAS_PHONE_NUMBER)

                        if (nameIndex != -1) {
                            val pickedName = c.getString(nameIndex)
                            if (!pickedName.isNullOrBlank() && name.isBlank()) {
                                name = pickedName
                            }
                        }

                        val contactId = if (idIndex != -1) c.getString(idIndex) else null
                        val hasPhone = if (hasPhoneIndex != -1) c.getInt(hasPhoneIndex) > 0 else true

                        if (contactId != null && hasPhone) {
                            // Query Phone number
                            val phoneCursor = context.contentResolver.query(
                                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                                null,
                                "${ContactsContract.CommonDataKinds.Phone.CONTACT_ID} = ?",
                                arrayOf(contactId),
                                null
                            )
                            phoneCursor?.use { pc ->
                                if (pc.moveToFirst()) {
                                    val pIndex = pc.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
                                    if (pIndex != -1) {
                                        val rawNumber = pc.getString(pIndex)
                                        phone = rawNumber.replace(Regex("[^0-9+]"), "")
                                    }
                                }
                            }

                            // Query Email
                            val emailCursor = context.contentResolver.query(
                                ContactsContract.CommonDataKinds.Email.CONTENT_URI,
                                null,
                                "${ContactsContract.CommonDataKinds.Email.CONTACT_ID} = ?",
                                arrayOf(contactId),
                                null
                            )
                            emailCursor?.use { ec ->
                                if (ec.moveToFirst()) {
                                    val eIndex = ec.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
                                    if (eIndex != -1) {
                                        val pickedEmail = ec.getString(eIndex)
                                        if (!pickedEmail.isNullOrBlank() && email.isBlank()) {
                                            email = pickedEmail
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Toast.makeText(context, "Contact imported successfully", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Could not read contact: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = Color.White,
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 12.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = if (existingParty != null) "Edit Party" else "Add New Customer / Vendor",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )
                    Text(
                        text = "Master directory record",
                        fontSize = 11.5.sp,
                        color = textMuted
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    // Import Contact Quick Action
                    Surface(
                        shape = RoundedCornerShape(20.dp),
                        color = Color(0xFFEEF2FF),
                        border = BorderStroke(1.dp, Color(0xFFC7D2FE)),
                        modifier = Modifier.clickable { contactPickerLauncher.launch(null) }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Icon(Icons.Default.ContactPhone, contentDescription = "Pick Contact", tint = primaryIndigo, modifier = Modifier.size(14.dp))
                            Text("Phone Contacts", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = primaryIndigo)
                        }
                    }

                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.background(Color(0xFFF1F5F9), CircleShape).size(32.dp)
                    ) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = textMuted, modifier = Modifier.size(16.dp))
                    }
                }
            }

            // Party Type Selector
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Customer", "Vendor", "Both").forEach { t ->
                    val isSel = partyType == t
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = if (isSel) primaryIndigo else Color(0xFFF1F5F9),
                        modifier = Modifier.weight(1f).clickable { partyType = t }
                    ) {
                        Text(
                            text = t,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isSel) Color.White else textDark,
                            modifier = Modifier.padding(vertical = 10.dp),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                    }
                }
            }

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Legal Entity / Party Name *") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = tradeName,
                onValueChange = { tradeName = it },
                label = { Text("Trade Name (Optional)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = gstin,
                    onValueChange = { gstin = it },
                    label = { Text("GSTIN") },
                    modifier = Modifier.weight(1.2f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = pan,
                    onValueChange = { pan = it },
                    label = { Text("PAN") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = phone,
                    onValueChange = { phone = it },
                    label = { Text("Phone / Mobile") },
                    trailingIcon = {
                        IconButton(onClick = { contactPickerLauncher.launch(null) }) {
                            Icon(Icons.Default.ContactPhone, contentDescription = "Pick from contacts", tint = primaryIndigo, modifier = Modifier.size(18.dp))
                        }
                    },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Email Address") },
                    modifier = Modifier.weight(1.2f),
                    singleLine = true
                )
            }

            OutlinedTextField(
                value = billingAddress,
                onValueChange = { billingAddress = it },
                label = { Text("Billing Address") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = state,
                    onValueChange = { state = it },
                    label = { Text("State") },
                    modifier = Modifier.weight(1.2f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = pincode,
                    onValueChange = { pincode = it },
                    label = { Text("Pincode") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            Button(
                onClick = {
                    if (name.isBlank()) {
                        Toast.makeText(context, "Please enter party legal name", Toast.LENGTH_SHORT).show()
                        return@Button
                    }
                    val party = PartyDto(
                        id = existingParty?.id ?: "",
                        partyType = partyType,
                        name = name,
                        tradeName = tradeName,
                        gstin = gstin,
                        pan = pan,
                        phone = phone,
                        email = email,
                        billingAddress = billingAddress,
                        state = state,
                        pincode = pincode
                    )
                    onSubmit(party)
                },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                modifier = Modifier.fillMaxWidth().height(48.dp)
            ) {
                Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (existingParty != null) "Update Party Record" else "Save to Master Directory", fontWeight = FontWeight.Bold)
            }

            // Save to phone contacts action
            if (phone.isNotBlank() || name.isNotBlank()) {
                OutlinedButton(
                    onClick = {
                        try {
                            val intent = Intent(ContactsContract.Intents.Insert.ACTION).apply {
                                type = ContactsContract.RawContacts.CONTENT_TYPE
                                putExtra(ContactsContract.Intents.Insert.NAME, name)
                                if (phone.isNotBlank()) {
                                    putExtra(ContactsContract.Intents.Insert.PHONE, phone)
                                    putExtra(ContactsContract.Intents.Insert.PHONE_TYPE, ContactsContract.CommonDataKinds.Phone.TYPE_WORK)
                                }
                                if (email.isNotBlank()) {
                                    putExtra(ContactsContract.Intents.Insert.EMAIL, email)
                                    putExtra(ContactsContract.Intents.Insert.EMAIL_TYPE, ContactsContract.CommonDataKinds.Email.TYPE_WORK)
                                }
                                if (tradeName.isNotBlank() || partyType.isNotBlank()) {
                                    putExtra(ContactsContract.Intents.Insert.COMPANY, tradeName.ifBlank { name })
                                    putExtra(ContactsContract.Intents.Insert.JOB_TITLE, "$partyType (VR HERE)")
                                }
                                if (billingAddress.isNotBlank()) {
                                    putExtra(ContactsContract.Intents.Insert.POSTAL, "$billingAddress, $state $pincode".trim().trim(','))
                                }
                            }
                            context.startActivity(intent)
                        } catch (e: Exception) {
                            Toast.makeText(context, "Cannot open contacts app: ${e.message}", Toast.LENGTH_SHORT).show()
                        }
                    },
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, primaryIndigo),
                    modifier = Modifier.fillMaxWidth().height(44.dp)
                ) {
                    Icon(Icons.Default.PersonAddAlt1, contentDescription = null, tint = primaryIndigo, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Save Party to Phone Contacts", color = primaryIndigo, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
