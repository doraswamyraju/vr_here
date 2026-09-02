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

const loadRazorpaySDK = () => {
  return new Promise((resolve) => {
    if (typeof window !== 'undefined' && window.Razorpay) {
      return resolve(true);
    }

    const existingScript = document.querySelector('script[src*="checkout.razorpay.com"]');
    if (existingScript) {
      let attempts = 0;
      const checkInterval = setInterval(() => {
        attempts++;
        if (typeof window !== 'undefined' && window.Razorpay) {
          clearInterval(checkInterval);
          return resolve(true);
        }
        if (attempts > 25) { // 2.5s timeout for existing script
          clearInterval(checkInterval);
          try {
            existingScript.remove();
          } catch (e) {}
          injectScript();
        }
      }, 100);
      return;
    }

    injectScript();

    function injectScript() {
      const script = document.createElement('script');
      script.src = 'https://checkout.razorpay.com/v1/checkout.js';
      script.async = true;
      script.onload = () => {
        if (typeof window !== 'undefined' && window.Razorpay) {
          resolve(true);
        } else {
          setTimeout(() => resolve(!!(typeof window !== 'undefined' && window.Razorpay)), 200);
        }
      };
      script.onerror = () => {
        console.error('[Razorpay Checkout] Failed to load Razorpay script.');
        resolve(false);
      };
      document.head.appendChild(script);

      setTimeout(() => {
        resolve(!!(typeof window !== 'undefined' && window.Razorpay));
      }, 5000);
    }
  });
};

export const launchRazorpayCheckout = async ({
  serviceName,
  selectedPlan,
  packageName,
  amount,
  price,
  formData = {},
  customerName: directCustomerName,
  customerEmail: directCustomerEmail,
  customerPhone: directCustomerPhone,
  token,
  onSubmittingChange,
  onSuccess,
  onFailure
}) => {
  try {
    onSubmittingChange?.(true);

    const isLoaded = await loadRazorpaySDK();
    if (!isLoaded || typeof window === 'undefined' || !window.Razorpay) {
      throw new Error('Razorpay payment gateway script was blocked or could not be loaded. Please disable ad-blockers and try again.');
    }

    const rawPrice = amount ?? price ?? selectedPlan?.price ?? selectedPlan?.amount ?? 0;
    const cleanAmount = typeof rawPrice === 'string'
      ? Number(rawPrice.replace(/[^0-9]/g, '')) || 0
      : Number(rawPrice) || 0;

    if (cleanAmount <= 0) {
      throw new Error('Please select a valid package price.');
    }

    const currentSavedUser = (() => {
      try {
        return JSON.parse(localStorage.getItem('userInfo') || 'null');
      } catch {
        return null;
      }
    })();

    const cleanServiceName = serviceName || selectedPlan?.name || packageName || 'Business Service';
    const cleanPackageName = packageName || selectedPlan?.name || 'Standard Package';
    const customerName = directCustomerName || formData?.name || currentSavedUser?.name || 'VR HERE Client';
    const email = directCustomerEmail || formData?.email || currentSavedUser?.email || 'client@vrhere.in';
    const phone = directCustomerPhone || formData?.phone || currentSavedUser?.phone || '9999999999';
    const authToken = token || localStorage.getItem('token') || currentSavedUser?.token;

    const checkoutPayload = {
      serviceName: cleanServiceName,
      packageName: cleanPackageName,
      amount: cleanAmount,
      customerName,
      email,
      phone,
      referralCode: formData?.referralCode || ''
    };

    console.log('[Razorpay Checkout] Requesting checkout order from backend:', checkoutPayload);

    const { data: checkoutOrder } = await axios.post(
      '/api/payments/checkout-order',
      checkoutPayload,
      getAuthConfig(authToken)
    );

    console.log('[Razorpay Checkout] Received checkout order:', checkoutOrder);

    if (!checkoutOrder?.key || !checkoutOrder?.orderId) {
      throw new Error(checkoutOrder?.message || 'Failed to initialize payment gateway order from server.');
    }

    const options = {
      key: checkoutOrder.key,
      amount: checkoutOrder.amount,
      currency: checkoutOrder.currency || 'INR',
      name: 'VR HERE Business Solutions',
      description: `Payment for ${cleanPackageName}`,
      order_id: checkoutOrder.orderId,
      handler: async function (response) {
        try {
          console.log('[Razorpay Checkout] Handling payment response verification:', response);
          const { data } = await axios.post(
            '/api/payments/verify',
            {
              ...checkoutPayload,
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature
            },
            getAuthConfig(authToken)
          );

          persistAuthFromPayment(data);
          onSubmittingChange?.(false);
          if (onSuccess) {
            await onSuccess(data);
          }
        } catch (error) {
          console.error('[Razorpay Checkout] Verification error:', error);
          onSubmittingChange?.(false);
          if (onFailure) {
            onFailure(error);
          }
        }
      },
      prefill: {
        name: customerName,
        email: email,
        contact: phone
      },
      notes: {
        serviceName: cleanServiceName,
        packageName: cleanPackageName,
        referralCode: formData?.referralCode || ''
      },
      theme: {
        color: '#DC2626'
      },
      modal: {
        ondismiss: function () {
          console.log('[Razorpay Checkout] Modal dismissed by user');
          onSubmittingChange?.(false);
        }
      }
    };

    const razorpayInstance = new window.Razorpay(options);
    razorpayInstance.on('payment.failed', function (response) {
      console.error('[Razorpay Checkout] Payment failed event:', response);
      onSubmittingChange?.(false);
      onFailure?.(response.error || new Error('Payment was declined or cancelled.'));
    });
    
    razorpayInstance.open();

    setTimeout(() => {
      onSubmittingChange?.(false);
    }, 2000);
  } catch (error) {
    console.error('[Razorpay Checkout] Error:', error);
    onSubmittingChange?.(false);
    onFailure?.(error);
  }
};
