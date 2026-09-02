import axios from 'axios';

const getAuthConfig = (token) => (
  token
    ? { headers: { Authorization: `Bearer ${token}` } }
    : {}
);

const persistAuthFromPayment = (paymentResponse) => {
  if (paymentResponse?.resetLinkSent) {
    localStorage.removeItem('token');
    localStorage.removeItem('userInfo');
    return;
  }

  const auth = paymentResponse?.auth;
  if (!auth?.token) return;

  localStorage.setItem('token', auth.token);
  localStorage.setItem('userInfo', JSON.stringify(auth));
};

const loadRazorpaySDK = () => {
  return new Promise((resolve) => {
    if (window.Razorpay) {
      return resolve(true);
    }
    const existingScript = document.querySelector('script[src*="checkout.razorpay.com"]');
    if (existingScript) {
      existingScript.addEventListener('load', () => resolve(true));
      existingScript.addEventListener('error', () => resolve(false));
      return;
    }
    const script = document.createElement('script');
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    script.onload = () => resolve(true);
    script.onerror = () => resolve(false);
    document.head.appendChild(script);
  });
};

export const launchRazorpayCheckout = async ({
  serviceName,
  selectedPlan,
  formData = {},
  token,
  onSubmittingChange,
  onSuccess,
  onFailure
}) => {
  try {
    const isLoaded = await loadRazorpaySDK();
    if (!isLoaded || !window.Razorpay) {
      throw new Error('Razorpay SDK failed to load. Please disable ad-blockers or check your connection.');
    }

    onSubmittingChange?.(true);

    const rawPrice = selectedPlan?.price ?? selectedPlan?.amount ?? 0;
    const cleanAmount = typeof rawPrice === 'string'
      ? Number(rawPrice.replace(/[^0-9]/g, '')) || 0
      : Number(rawPrice) || 0;

    const currentSavedUser = (() => {
      try {
        return JSON.parse(localStorage.getItem('userInfo') || 'null');
      } catch {
        return null;
      }
    })();

    const customerName = formData?.name || currentSavedUser?.name || 'VR HERE Client';
    const email = formData?.email || currentSavedUser?.email || 'client@vrhere.in';
    const phone = formData?.phone || currentSavedUser?.phone || '';

    const checkoutPayload = {
      serviceName: serviceName || selectedPlan?.name || 'Business Service',
      packageName: selectedPlan?.name || 'Standard Package',
      amount: cleanAmount,
      customerName,
      email,
      phone,
      referralCode: formData?.referralCode || ''
    };

    const { data: checkoutOrder } = await axios.post(
      '/api/payments/checkout-order',
      checkoutPayload,
      getAuthConfig(token || currentSavedUser?.token)
    );

    if (!checkoutOrder?.key || !checkoutOrder?.orderId) {
      throw new Error('Backend did not return a valid Razorpay checkout order.');
    }

    const options = {
      key: checkoutOrder.key,
      amount: checkoutOrder.amount,
      currency: checkoutOrder.currency || 'INR',
      name: 'VR HERE Business Solutions',
      description: `Payment for ${selectedPlan?.name || serviceName}`,
      image: '/logo.png',
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
            getAuthConfig(token || currentSavedUser?.token)
          );

          persistAuthFromPayment(data);
          onSubmittingChange?.(false);
          onSuccess?.(data);
        } catch (error) {
          onSubmittingChange?.(false);
          onFailure?.(error);
        }
      },
      prefill: {
        name: customerName,
        email: email,
        contact: phone
      },
      notes: {
        serviceName: serviceName || selectedPlan?.name,
        packageName: selectedPlan?.name,
        referralCode: formData?.referralCode || ''
      },
      theme: {
        color: '#DC2626'
      },
      modal: {
        ondismiss: function () {
          onSubmittingChange?.(false);
        }
      }
    };

    const razorpayInstance = new window.Razorpay(options);
    razorpayInstance.on('payment.failed', function (response) {
      onSubmittingChange?.(false);
      onFailure?.(response.error || new Error('Payment failed'));
    });
    razorpayInstance.open();
  } catch (error) {
    onSubmittingChange?.(false);
    onFailure?.(error);
  }
};
