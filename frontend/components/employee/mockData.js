export const dummyNotifications = [
  {
    _id: 'n1',
    title: 'New Assignment',
    message: 'You have been assigned a new GST registration case.',
    createdAt: new Date().toISOString()
  },
  {
    _id: 'n2',
    title: 'Document Received',
    message: 'Client uploaded pending KYC document.',
    createdAt: new Date(Date.now() - 3600 * 1000).toISOString()
  }
];

export const dummyTickets = [
  {
    _id: 't1',
    subject: 'Need update on filing status',
    status: 'Open',
    createdAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
  },
  {
    _id: 't2',
    subject: 'Unable to upload PAN copy',
    status: 'Pending',
    createdAt: new Date(Date.now() - 24 * 3600 * 1000).toISOString()
  }
];

