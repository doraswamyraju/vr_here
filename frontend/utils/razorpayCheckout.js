import axios from 'axios';
import { RAZORPAY_KEY_ID } from '../config';

const getAuthConfig = (token) => (
  token
    ? { headers: { Authorization: `Bearer ${token}` } }
    : {}
);

export const launchRazorpayCheckout = async ({
  serviceName,
  selectedPlan,
  formData,
  token,
  onSubmittingChange,
  onSuccess,
  onFailure
}) => {
  try {
    if (!window.Razorpay) {
      throw new Error('Razorpay SDK failed to load. Please check your internet connection or disable ad-blockers.');
    }

    onSubmittingChange(true);

    const checkoutPayload = {
      serviceName,
      packageName: selectedPlan.name,
      amount: selectedPlan.price,
      customerName: formData.name,
      email: formData.email,
      phone: formData.phone
    };

    const { data: checkoutOrder } = await axios.post(
      '/api/payments/checkout-order',
      checkoutPayload,
      getAuthConfig(token)
    );

    const options = {
      key: checkoutOrder.key || RAZORPAY_KEY_ID,
      amount: checkoutOrder.amount,
      currency: checkoutOrder.currency || 'INR',
      name: 'VR HERE Business Solutions',
      description: `Payment for ${selectedPlan.name}`,
      image: 'https://vrhere.in/logo.png',
      order_id: checkoutOrder.orderId,
      handler: async function (response) {
        try {
          const { data } = await axios.post(
            '/api/payments/verify',
            {
              ...checkoutPayload,
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature
            },
            getAuthConfig(token)
          );

          onSubmittingChange(false);
          onSuccess?.(data);
        } catch (error) {
          onSubmittingChange(false);
          onFailure?.(error);
        }
      },
      prefill: {
        name: formData.name,
        email: formData.email,
        contact: formData.phone
      },
      notes: {
        serviceName,
        packageName: selectedPlan.name
      },
      theme: {
        color: '#DC2626'
      }
    };

    const razorpayInstance = new window.Razorpay(options);
    razorpayInstance.on('payment.failed', function (response) {
      onSubmittingChange(false);
      onFailure?.(response.error || new Error('Payment failed'));
    });
    razorpayInstance.open();
  } catch (error) {
    onSubmittingChange(false);
    onFailure?.(error);
  }
};
