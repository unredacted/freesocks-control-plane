/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as account from "../account.js";
import type * as accountId from "../accountId.js";
import type * as adminApi from "../adminApi.js";
import type * as admins from "../admins.js";
import type * as apiTokens from "../apiTokens.js";
import type * as appSettings from "../appSettings.js";
import type * as audit from "../audit.js";
import type * as auth from "../auth.js";
import type * as backendServers from "../backendServers.js";
import type * as backends from "../backends.js";
import type * as billing from "../billing.js";
import type * as clients from "../clients.js";
import type * as connectionProfiles from "../connectionProfiles.js";
import type * as cronHeartbeat from "../cronHeartbeat.js";
import type * as crons from "../crons.js";
import type * as freeTier from "../freeTier.js";
import type * as health from "../health.js";
import type * as http from "../http.js";
import type * as keyEpochs from "../keyEpochs.js";
import type * as keyRevocations from "../keyRevocations.js";
import type * as lib_accountId from "../lib/accountId.js";
import type * as lib_audit from "../lib/audit.js";
import type * as lib_backends_mock from "../lib/backends/mock.js";
import type * as lib_backends_outline from "../lib/backends/outline.js";
import type * as lib_backends_registry from "../lib/backends/registry.js";
import type * as lib_backends_remnawave from "../lib/backends/remnawave.js";
import type * as lib_backends_types from "../lib/backends/types.js";
import type * as lib_billingConfig from "../lib/billingConfig.js";
import type * as lib_clientCatalog from "../lib/clientCatalog.js";
import type * as lib_captcha from "../lib/captcha.js";
import type * as lib_connectionProfiles from "../lib/connectionProfiles.js";
import type * as lib_cookies from "../lib/cookies.js";
import type * as lib_crypto from "../lib/crypto.js";
import type * as lib_e2ee from "../lib/e2ee.js";
import type * as lib_e2eeCrypto from "../lib/e2eeCrypto.js";
import type * as lib_http from "../lib/http.js";
import type * as lib_issuance from "../lib/issuance.js";
import type * as lib_membershipCode from "../lib/membershipCode.js";
import type * as lib_pop from "../lib/pop.js";
import type * as lib_processors_nowpayments from "../lib/processors/nowpayments.js";
import type * as lib_processors_paypal from "../lib/processors/paypal.js";
import type * as lib_processors_stripe from "../lib/processors/stripe.js";
import type * as lib_processors_types from "../lib/processors/types.js";
import type * as lib_rateLimitPolicy from "../lib/rateLimitPolicy.js";
import type * as lib_supportId from "../lib/supportId.js";
import type * as lib_themeConfig from "../lib/themeConfig.js";
import type * as lib_verificationConfig from "../lib/verificationConfig.js";
import type * as lifecycle from "../lifecycle.js";
import type * as membershipCodes from "../membershipCodes.js";
import type * as mirrorProviders from "../mirrorProviders.js";
import type * as publicConfig from "../publicConfig.js";
import type * as rateLimits from "../rateLimits.js";
import type * as replayGuard from "../replayGuard.js";
import type * as retention from "../retention.js";
import type * as seed from "../seed.js";
import type * as sessions from "../sessions.js";
import type * as storage from "../storage.js";
import type * as subscriptions from "../subscriptions.js";
import type * as supportId from "../supportId.js";
import type * as tiers from "../tiers.js";
import type * as users from "../users.js";
import type * as webauthn from "../webauthn.js";
import type * as webhooks from "../webhooks.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  account: typeof account;
  accountId: typeof accountId;
  adminApi: typeof adminApi;
  admins: typeof admins;
  apiTokens: typeof apiTokens;
  appSettings: typeof appSettings;
  audit: typeof audit;
  auth: typeof auth;
  backendServers: typeof backendServers;
  backends: typeof backends;
  billing: typeof billing;
  clients: typeof clients;
  connectionProfiles: typeof connectionProfiles;
  cronHeartbeat: typeof cronHeartbeat;
  crons: typeof crons;
  freeTier: typeof freeTier;
  health: typeof health;
  http: typeof http;
  keyEpochs: typeof keyEpochs;
  keyRevocations: typeof keyRevocations;
  "lib/accountId": typeof lib_accountId;
  "lib/audit": typeof lib_audit;
  "lib/backends/mock": typeof lib_backends_mock;
  "lib/backends/outline": typeof lib_backends_outline;
  "lib/backends/registry": typeof lib_backends_registry;
  "lib/backends/remnawave": typeof lib_backends_remnawave;
  "lib/backends/types": typeof lib_backends_types;
  "lib/billingConfig": typeof lib_billingConfig;
  "lib/clientCatalog": typeof lib_clientCatalog;
  "lib/captcha": typeof lib_captcha;
  "lib/connectionProfiles": typeof lib_connectionProfiles;
  "lib/cookies": typeof lib_cookies;
  "lib/crypto": typeof lib_crypto;
  "lib/e2ee": typeof lib_e2ee;
  "lib/e2eeCrypto": typeof lib_e2eeCrypto;
  "lib/http": typeof lib_http;
  "lib/issuance": typeof lib_issuance;
  "lib/membershipCode": typeof lib_membershipCode;
  "lib/pop": typeof lib_pop;
  "lib/processors/nowpayments": typeof lib_processors_nowpayments;
  "lib/processors/paypal": typeof lib_processors_paypal;
  "lib/processors/stripe": typeof lib_processors_stripe;
  "lib/processors/types": typeof lib_processors_types;
  "lib/rateLimitPolicy": typeof lib_rateLimitPolicy;
  "lib/supportId": typeof lib_supportId;
  "lib/themeConfig": typeof lib_themeConfig;
  "lib/verificationConfig": typeof lib_verificationConfig;
  lifecycle: typeof lifecycle;
  membershipCodes: typeof membershipCodes;
  mirrorProviders: typeof mirrorProviders;
  publicConfig: typeof publicConfig;
  rateLimits: typeof rateLimits;
  replayGuard: typeof replayGuard;
  retention: typeof retention;
  seed: typeof seed;
  sessions: typeof sessions;
  storage: typeof storage;
  subscriptions: typeof subscriptions;
  supportId: typeof supportId;
  tiers: typeof tiers;
  users: typeof users;
  webauthn: typeof webauthn;
  webhooks: typeof webhooks;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
