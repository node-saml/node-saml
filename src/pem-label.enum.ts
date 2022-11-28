export const PemLabel = {
  CERTIFICATE: "CERTIFICATE" as const,
  PUBLIC_KEY: "PUBLIC KEY" as const,
  PRIVATE_KEY: "PRIVATE KEY" as const,
};

export type PemLabelId = typeof PemLabel[keyof typeof PemLabel];
