import axios from 'axios';

const getAuthConfig = (token) => (
  token
    ? { headers: { Authorization: `Bearer ${token}` } }
    : {}
);

const persistAuthFromPayment = (paymentResponse) => {
  const auth = paymentResponse?.auth;
  if (!auth?.token) return;

  localStorage.setItem('token', auth.token);
  localStorage.setItem('userInfo', JSON.stringify(auth));
};

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

    if (!checkoutOrder?.key || !checkoutOrder?.orderId) {
      throw new Error('Backend did not return a valid Razorpay checkout order. Check backend env and deployment restart.');
    }

    const options = {
      key: checkoutOrder.key,
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

          persistAuthFromPayment(data);
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
