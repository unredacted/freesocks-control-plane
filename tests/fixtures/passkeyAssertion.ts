// Fixed localhost WebAuthn assertions made by one disposable Ed25519 credential.
// Each signs a different realm and PoP key. Only public test material is retained.
export const passkeyNonce = 'DHvoU78fFHJPJjqrp2t6qHByTnHLT9--F6aEyH8l2q8';
export const credentialPublicKey = 'pAEBAycgBiFYILH4d73HEJgvt+S6Gh6acI+wkELKGQNShVvX74gss73x';
export const passkeyExamples = {
  member: {
    alternatePub: 'H4d73HEJgvt-S6Gh6acI-wkELKGQNShVvX74gss73xA',
    alg: 'EdDSA',
    pub: 'xlCZa0F90zRZUpFO3BeQIUzkGPm82dL9HEQB1J8FaeU',
    challenge: '6ugd8_aCha5q9cm4DOnhvvtPdOEWUn5yrY5A28wELtA',
    signature:
      'TmjlDGvKpShUsLbdNtKTr4cAgUMEZfdfRg226p-1tg7e9vp-ev30haIeS87n-ZWC8l-XYOwwKsrZ9dsVF2ZwBg',
  },
  admin: {
    alternatePub:
      'BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU',
    alg: 'ES256',
    pub: 'BKVo8tL8C9u4dsMjoqbskBxKeY3dTHVl8MqUd8_64Gtu9K0DbD-NJu3PBJnnj8xMU0jC6XYDoWCH6W6Uh9w5ElE',
    challenge: 'LaKkYML2iP2MWSw-BfnJEwUstCZV2a7I0A0tpk41gZ0',
    signature:
      'R1EzMWLBzVQjB7yLD53T5RGCqHRDHv1fAskWGMQAhoESKIBkcVGVwpHXNnU8vMNHbP4IOLYSgh-R7kWswkjmCw',
  },
} as const;

export function signedAssertion(realm: keyof typeof passkeyExamples) {
  const { challenge, signature } = passkeyExamples[realm];
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge,
      origin: 'http://localhost:5173',
    }),
  ).toString('base64url');
  return {
    id: 'cred-1',
    rawId: 'cred-1',
    type: 'public-key' as const,
    clientExtensionResults: {},
    response: {
      authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAABw',
      clientDataJSON,
      signature,
    },
  };
}
