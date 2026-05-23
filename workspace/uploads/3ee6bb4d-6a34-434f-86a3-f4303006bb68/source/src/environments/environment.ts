// Gatillo 4 y 5: Secretos expuestos y CORS laxo
export const environment = {
  production: false,
  apiKey: "ABCDEF1234567890SECRET_TOKEN",
  allowedOrigins: ["*"],
  corsConfig: 'origin: "*"'
};
