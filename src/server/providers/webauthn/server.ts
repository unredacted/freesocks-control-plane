import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

export interface WebAuthnConfig {
  rpId: string;
  rpName: string;
  /**
   * Allowed page origin(s). Pass a single origin (`https://beta.freesocks.org`)
   * or a comma-separated list (`https://beta.freesocks.org,https://freesocks.org`)
   * if the same `rpId` is shared across multiple deployments.
   */
  origin: string;
}

export class WebAuthnService {
  private readonly origins: string[];

  constructor(private readonly config: WebAuthnConfig) {
    this.origins = config.origin
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean);
  }

  async generateRegistration(opts: {
    userId: Uint8Array;
    userName: string;
    userDisplayName: string;
    excludeCredentialIds?: string[];
  }) {
    return generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userID: new Uint8Array(opts.userId.slice()),
      userName: opts.userName,
      userDisplayName: opts.userDisplayName,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials: opts.excludeCredentialIds?.map((id) => ({ id })),
    });
  }

  async verifyRegistration(response: RegistrationResponseJSON, expectedChallenge: string) {
    return verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origins.length === 1 ? this.origins[0]! : this.origins,
      expectedRPID: this.config.rpId,
    });
  }

  async generateAuthentication(opts: { allowCredentialIds?: string[] }) {
    return generateAuthenticationOptions({
      rpID: this.config.rpId,
      userVerification: 'preferred',
      allowCredentials: opts.allowCredentialIds?.map((id) => ({ id })),
    });
  }

  async verifyAuthentication(opts: {
    response: AuthenticationResponseJSON;
    expectedChallenge: string;
    credential: {
      id: string;
      publicKey: Uint8Array;
      counter: number;
    };
  }) {
    return verifyAuthenticationResponse({
      response: opts.response,
      expectedChallenge: opts.expectedChallenge,
      expectedOrigin: this.origins.length === 1 ? this.origins[0]! : this.origins,
      expectedRPID: this.config.rpId,
      credential: {
        id: opts.credential.id,
        publicKey: new Uint8Array(opts.credential.publicKey.slice()),
        counter: opts.credential.counter,
      },
    });
  }
}
