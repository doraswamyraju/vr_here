import SwiftUI

struct CustomerSupportTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Support Communication Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Raise new ticket card
                VStack(alignment: .leading, spacing: 12) {
                    Text("Open New Query Ticket")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    CustomInputField(label: "Subject", placeholder: "Short summary", iconName: "tag", text: $viewModel.ticketSubject)
                    CustomInputField(label: "Description", placeholder: "Detail issues", iconName: "doc.text", text: $viewModel.ticketDescription)
                    
                    Button(action: {
                        viewModel.createSupportTicket()
                    }) {
                        Text("SUBMIT TICKET QUERY")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                // History of tickets
                if !viewModel.tickets.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Ticket Logs")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 20)
                        
                        ForEach(viewModel.tickets) { ticket in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(ticket.subject)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(ticket.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(ticket.status == "Open" ? .green : .gray)
                                }
                                Text(ticket.description)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                ForEach(ticket.messages) { msg in
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(msg.sender?.name ?? "System Executive")
                                                .font(.system(size: 9, weight: .bold))
                                                .foregroundColor(.blue)
                                            Text(msg.message)
                                                .font(.system(size: 11))
                                                .foregroundColor(.textDark)
                                        }
                                        Spacer()
                                    }
                                    .padding(8)
                                    .background(Color.bgLight)
                                    .cornerRadius(8)
                                }
                                
                                // Reply block
                                HStack {
                                    TextField("Type reply...", text: $viewModel.ticketReplyMessage)
                                        .font(.system(size: 12))
                                    Button(action: {
                                        viewModel.replyToTicket(ticketId: ticket.id)
                                    }) {
                                        Image(systemName: "paperplane.fill")
                                            .foregroundColor(.blue)
                                    }
                                }
                                .padding(8)
                                .background(Color.bgInput)
                                .cornerRadius(8)
                            }
                            .padding(14)
                            .glassCard()
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
