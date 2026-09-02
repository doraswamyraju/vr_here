import React from 'react';
import TicketCenter from '../tickets/TicketCenter';

export default function SupportView({ userInfo }) {
  return <TicketCenter userInfo={userInfo} userRole="client" />;
}
