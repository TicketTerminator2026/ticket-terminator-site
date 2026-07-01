// /.netlify/functions/config
// Returns public feature-flag configuration for the dashboard.
// No auth required — values are non-sensitive booleans only.

exports.handler = async () => {
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
    body: JSON.stringify({
      stripeEnabled: process.env.STRIPE_WEBHOOK_ENABLED === 'true',
    }),
  };
};
