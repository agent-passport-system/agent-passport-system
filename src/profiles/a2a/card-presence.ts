// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

/**
 * A2A 1.0 Agent Card signing payload (A2A 1.0 section 8.4.1).
 *
 * Before RFC 8785 canonicalization, a field that is neither REQUIRED nor marked
 * `optional` is omitted when it holds its Protocol Buffer default. The table
 * below was generated from `specification/a2a.proto` at tag v1.0.1
 * (sha256 e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016) for every message reachable from AgentCard.
 *
 * Kinds: `required` kept, `optional` kept when present, `implicit` string or `implicitBoolean` boolean
 * dropped at its declared default, `repeated` list or map dropped when empty, `message`
 * singular message or oneof member kept when present, even when empty.
 * Members the table does not define, and the contents of
 * `google.protobuf.Struct` values such as extension `params`, are kept as served.
 */

type FieldKind = 'required' | 'optional' | 'implicit' | 'implicitBoolean' | 'repeated' | 'message'
type FieldSpec = readonly [FieldKind, string | null]

const A2A_1_0_FIELDS: Readonly<Record<string, Readonly<Record<string, FieldSpec>>>> = {
  APIKeySecurityScheme: { description: ['implicit', null], location: ['required', null], name: ['required', null] },
  AgentCapabilities: { extendedAgentCard: ['optional', null], extensions: ['repeated', 'AgentExtension'], pushNotifications: ['optional', null], streaming: ['optional', null] },
  AgentCard: { capabilities: ['required', 'AgentCapabilities'], defaultInputModes: ['required', null], defaultOutputModes: ['required', null], description: ['required', null], documentationUrl: ['optional', null], iconUrl: ['optional', null], name: ['required', null], provider: ['message', 'AgentProvider'], securityRequirements: ['repeated', 'SecurityRequirement'], securitySchemes: ['repeated', 'map:SecurityScheme'], skills: ['required', 'AgentSkill'], supportedInterfaces: ['required', 'AgentInterface'], version: ['required', null] },
  AgentExtension: { description: ['implicit', null], params: ['message', null], required: ['implicitBoolean', null], uri: ['implicit', null] },
  AgentInterface: { protocolBinding: ['required', null], protocolVersion: ['required', null], tenant: ['implicit', null], url: ['required', null] },
  AgentProvider: { organization: ['required', null], url: ['required', null] },
  AgentSkill: { description: ['required', null], examples: ['repeated', null], id: ['required', null], inputModes: ['repeated', null], name: ['required', null], outputModes: ['repeated', null], securityRequirements: ['repeated', 'SecurityRequirement'], tags: ['required', null] },
  AuthorizationCodeOAuthFlow: { authorizationUrl: ['required', null], pkceRequired: ['implicitBoolean', null], refreshUrl: ['implicit', null], scopes: ['required', null], tokenUrl: ['required', null] },
  ClientCredentialsOAuthFlow: { refreshUrl: ['implicit', null], scopes: ['required', null], tokenUrl: ['required', null] },
  DeviceCodeOAuthFlow: { deviceAuthorizationUrl: ['required', null], refreshUrl: ['implicit', null], scopes: ['required', null], tokenUrl: ['required', null] },
  HTTPAuthSecurityScheme: { bearerFormat: ['implicit', null], description: ['implicit', null], scheme: ['required', null] },
  ImplicitOAuthFlow: { authorizationUrl: ['implicit', null], refreshUrl: ['implicit', null], scopes: ['repeated', 'map:string'] },
  MutualTlsSecurityScheme: { description: ['implicit', null] },
  OAuth2SecurityScheme: { description: ['implicit', null], flows: ['required', 'OAuthFlows'], oauth2MetadataUrl: ['implicit', null] },
  OAuthFlows: { authorizationCode: ['message', 'AuthorizationCodeOAuthFlow'], clientCredentials: ['message', 'ClientCredentialsOAuthFlow'], deviceCode: ['message', 'DeviceCodeOAuthFlow'], implicit: ['message', 'ImplicitOAuthFlow'], password: ['message', 'PasswordOAuthFlow'] },
  OpenIdConnectSecurityScheme: { description: ['implicit', null], openIdConnectUrl: ['required', null] },
  PasswordOAuthFlow: { refreshUrl: ['implicit', null], scopes: ['repeated', 'map:string'], tokenUrl: ['implicit', null] },
  SecurityRequirement: { schemes: ['repeated', 'map:StringList'] },
  SecurityScheme: { apiKeySecurityScheme: ['message', 'APIKeySecurityScheme'], httpAuthSecurityScheme: ['message', 'HTTPAuthSecurityScheme'], mtlsSecurityScheme: ['message', 'MutualTlsSecurityScheme'], oauth2SecurityScheme: ['message', 'OAuth2SecurityScheme'], openIdConnectSecurityScheme: ['message', 'OpenIdConnectSecurityScheme'] },
  StringList: { list: ['repeated', null] },
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isImplicitDefault(value: unknown, kind: FieldKind): boolean {
  return kind === 'implicitBoolean' ? value === false : kind === 'implicit' && value === ''
}

function isEmptyRepeated(value: unknown, child: string | null): boolean {
  return child?.startsWith('map:')
    ? isPlainObject(value) && Object.keys(value).length === 0
    : Array.isArray(value) && value.length === 0
}

function prune(value: unknown, message: string | null): unknown {
  if (message === null || message === 'string') return value
  if (message.startsWith('map:')) {
    if (!isPlainObject(value)) return value
    const item = message.slice(4)
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, prune(entry, item)]))
  }
  if (Array.isArray(value)) return value.map((entry) => prune(entry, message))
  if (!isPlainObject(value)) return value
  const fields = A2A_1_0_FIELDS[message] ?? {}
  const entries: [string, unknown][] = []
  for (const [name, entry] of Object.entries(value)) {
    const spec = Object.prototype.hasOwnProperty.call(fields, name) ? fields[name] : undefined
    if (spec === undefined) {
      entries.push([name, entry])
      continue
    }
    const [kind, child] = spec
    if (isImplicitDefault(entry, kind)) continue
    if (kind === 'repeated' && isEmptyRepeated(entry, child)) continue
    entries.push([name, prune(entry, child)])
  }
  return Object.fromEntries(entries)
}

/** The card without `signatures` and without A2A 1.0 default values, ready for JCS. */
export function a2aCardSigningObjectV1(card: Record<string, unknown>): Record<string, unknown> {
  const { signatures: _signatures, ...unsigned } = card
  return prune(unsigned, 'AgentCard') as Record<string, unknown>
}
