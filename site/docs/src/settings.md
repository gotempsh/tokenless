<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Settings

Instance-wide settings, under **Settings** in the console (admins only).
Changes reach every proxy at its next policy refresh.

## Other hosts

Agents send all their HTTPS traffic through the proxy. This decides what
happens to hosts that aren't one of their services:

- **Allow** (the default): the connection is passed through untouched.
  The proxy doesn't decrypt it or add any credential.
- **Block**: agents reach only the services in their session, plus the
  [always reachable](#always-reachable) hosts.

## Session lifetime

The longest session anyone may create, from 15 minutes up to 90 days;
7 days by default (an instance created before this default keeps the
1 hour it had). Sessions you hand an agent last at most this long; ones
`tokenless run --bundle` mints are renewed while the agent runs, so they
can stay short. A short lifetime limits how long a leaked session token
is useful.

## Always reachable

Hosts every session may reach even when other hosts are blocked, such as
package registries and documentation, one per line:
`registry.npmjs.org`, `*.pythonhosted.org` (one label), with `:port` for
ports other than 443. They are passed through untouched and never given a
credential.

## Private addresses

By default the proxy won't connect to loopback, private, link-local or
cloud metadata addresses, so an agent can't use it to reach your internal
network. Allow specific ranges here when a service you broker lives on
one. This applies to other hosts and to credential tests; a session's own
services are always reachable.

## Single sign-on

People can sign in with an OpenID Connect identity provider that sends
group membership (Okta, Microsoft Entra ID, Keycloak, Authentik and
others) instead of a password. Add one under **Settings → Single sign-on → Add a
provider**:

1. At the provider, register a web application with the **Redirect URI**
   the form shows: this instance's address followed by
   `/api/v1/auth/oidc/callback`. The address must be the one people's
   browsers use.
2. Enter the provider's **issuer URL** (its discovery document is read
   from `/.well-known/openid-configuration`), the **client ID** and,
   for a confidential client, the **client secret**. The secret is
   encrypted at rest and never shown again; leave the field empty when
   editing to keep it.
3. Map the provider's **groups** to roles. Someone in several mapped
   groups gets the highest role; someone in none is refused, and the
   message names the groups the provider sent so you can fix the mapping.
   Groups are read from the `groups` claim of the ID token, or of the
   user info when the token leaves it out; set another claim, or a dotted
   path such as `realm_access.roles`, for providers that put them
   elsewhere. Some providers send groups only for an extra scope.

The sign-in page then shows **Continue with *name***. The first sign-in
creates the account, named by the `preferred_username` claim unless you
choose another; a local account that already has the name is never taken
over, and the sign-in is refused instead. The role follows the person's
groups at every sign-in and cannot be changed by hand. Disabling the
account under **People** still locks them out.

People who sign in with a provider have no password or authenticator
here. When a sensitive action needs a fresh confirmation, they sign in at
the provider again in a popup window. Turning a provider off hides its
button and ends the sessions of everyone who signed in with it; a
provider people have signed in with can't be deleted, only turned off.

The browser is sent to the provider with PKCE and a nonce; the answer is
accepted once, only in the browser that asked, within 10 minutes. ID
tokens must be signed (RS, PS, ES or EdDSA; never `none` or a shared
secret) by a key in the provider's published key set, and are checked for
issuer, audience, expiry and nonce.

## Password sign-in

With a provider that is on, you can limit passwords to **local admins
only**. Everyone else then signs in with single sign-on, and the existing
sessions of local non-admin accounts stop working. Local admins keep their
password (and authenticator) to get in when the provider is down: the
sign-in page offers **Sign in with a local admin account** under the
provider buttons. Invites can then only create admins. The last provider
that is on can't be turned off or deleted while this is set.
