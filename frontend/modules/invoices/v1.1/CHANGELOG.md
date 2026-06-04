# Invoice Module Changelog

## v1.1
- Initial module setup
- Added support for auto-generating primary invoices on manual/direct checkout orders
- Implemented 499 expert consultation auto-adjustment option
- Implemented consecutive price change adjustment (subtracting previous amounts)
- Added split payment percentage selector with auto Razorpay link generation
- Configured Razorpay Webhook listener to handle auto-updating invoice status to `Paid` upon successful payment events (`payment_link.paid` and `payment.captured`)
