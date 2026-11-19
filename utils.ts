/**
 * @fileoverview Utils for CSP evaluator.
 * @author lwe@google.com (Lukas Weichselbaum)
 *
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import * as csp from './csp';


/**
 * Removes scheme from url.
 * @param url Url.
 * @return url without scheme.
 */
export function getSchemeFreeUrl(url: string): string {
  url = url.replace(/^\w[+\w.-]*:\/\//i, '');
  // Remove URL scheme.
  url = url.replace(/^\/\//, '');
  // Remove protocol agnostic "//"
  return url;
}

/**
 * Get the hostname from the given url string in a way that supports schemeless
 * URLs and wildcards (aka `*`) in hostnames
 */
export function getHostname(url: string): string {
  const hostname = new URL(
                       'https://' +
                       getSchemeFreeUrl(url)
                           .replace(':*', '')  // Remove wildcard port
                           .replace('*', 'wildcard_placeholder'))
                       .hostname.replace('wildcard_placeholder', '*');

  // Some browsers strip the brackets from IPv6 addresses when you access the
  // hostname. If the scheme free url starts with something that vaguely looks
  // like an IPv6 address and our parsed hostname doesn't have the brackets,
  // then we add them back to work around this
  const ipv6Regex = /^\[[\d:a-fA-F]+\]/;
  if (getSchemeFreeUrl(url).match(ipv6Regex) && !hostname.match(ipv6Regex)) {
    return '[' + hostname + ']';
  }
  return hostname;
}

function setScheme(u: string): string {
  if (u.startsWith('//')) {
    return u.replace('//', 'https://');
  }
  if (!/^[a-zA-Z][+a-zA-Z0-9.-]*:\/\//.test(u)) {
    // A host-source without a scheme ("example.com" or "example.com/path") is
    // scheme relative and needs an authority marker before the URL parser can
    // resolve it.
    return 'https://' + u;
  }
  return u;
}

/**
 * Default ports of the schemes that can appear in CSP source expressions.
 * https://url.spec.whatwg.org/#scheme-registered
 */
const DEFAULT_PORTS: ReadonlyMap<string, number> = new Map([
  ['ftp:', 21],
  ['http:', 80],
  ['ws:', 80],
  ['https:', 443],
  ['wss:', 443],
]);

/**
 * A CSP host-source expression parsed into its individual components.
 * https://w3c.github.io/webappsec-csp/#host-source
 */
export interface SourceExpression {
  /** Parsed expression, credentials / IPv6 brackets and port are preserved. */
  url: URL;
  /** Original scheme, or empty string for scheme-relative ("//host") sources. */
  scheme: string;
  /** Host in lower case, with IPv6 brackets preserved and `*` wildcards intact. */
  host: string;
  /** Host with a leading subdomain wildcard removed (e.g. "*.a.com" -> "a.com"). */
  wildcardFreeHost: string;
  /** Whether the host starts with a subdomain wildcard ("*."). */
  hasHostWildcard: boolean;
  /** Whether the host is the standalone wildcard "*". */
  hasBareWildcard: boolean;
  /** Explicitly specified port, or null if none was given. */
  port: number|null;
  /** Whether the source allows any port (":*"). */
  hasPortWildcard: boolean;
  path: string;
  /** Whether a non-empty path component was specified. */
  hasPath: boolean;
}

/**
 * Parses a CSP source expression (or a bypass URL) into its components.
 * Wildcards in the host and a wildcard port ("*") are preserved in the
 * returned structure, while the underlying `URL` keeps the original
 * credentials, IPv6 brackets and explicit port as evidence.
 * @return The parsed expression or null if it cannot be parsed as a URL.
 */
export function parseSourceExpression(expression: string): SourceExpression
    |null {
  let hasPortWildcard = false;
  let normalizedExpression = expression;

  // Detect and strip a wildcard port before handing the expression to the URL
  // parser, as "*" is not a valid port on its own.
  if (/:\*(?=[/?#]|$)/.test(normalizedExpression)) {
    hasPortWildcard = true;
    normalizedExpression = normalizedExpression.replace(':*', '');
  }

  // non-Chromium browsers don't support wildcards in domain names. We work
  // around this by replacing the wildcard with `wildcard_placeholder` before
  // parsing the domain and using that as a magic string. This magic string is
  // encapsulated in this function such that callers do not have to worry about
  // this detail.
  normalizedExpression =
      normalizedExpression.replace('*', 'wildcard_placeholder');

  let parsed: URL;
  try {
    parsed = new URL(setScheme(normalizedExpression));
  } catch {
    return null;
  }

  // A scheme-relative source ("//host") or a bare host has no scheme part and
  // therefore matches resources of any scheme.
  const hasScheme = /^[a-zA-Z][+a-zA-Z0-9.-]*:\/\//.test(expression);
  const scheme = hasScheme ? parsed.protocol.toLowerCase() : '';

  let host =
      parsed.hostname.toLowerCase().replace('wildcard_placeholder', '*');

  // Some browsers strip the brackets from IPv6 addresses when you access the
  // hostname. If the expression starts with something that vaguely looks like
  // an IPv6 address and our parsed host doesn't have the brackets, we add them
  // back to work around this.
  const ipv6Regex = /^\[[\d:a-fA-F]+\]$/;
  const rawAuthority = getSchemeFreeUrl(expression);
  if (rawAuthority.match(/^\[[\d:a-fA-F]+\]/) && !host.match(ipv6Regex)) {
    host = '[' + host + ']';
  }

  const hasBareWildcard = host === '*';
  const hasHostWildcard = host.startsWith('*.');
  const wildcardFreeHost =
      hasHostWildcard ? host.slice(2) : (hasBareWildcard ? '' : host);

  // The wildcard port has already been stripped above, so the parsed port is
  // always either an explicitly specified port or empty (default port).
  const port: number|null = parsed.port === '' ? null : Number(parsed.port);

  const path = parsed.pathname;

  return {
    url: parsed,
    scheme,
    host,
    wildcardFreeHost,
    hasHostWildcard,
    hasBareWildcard,
    port,
    hasPortWildcard,
    path,
    hasPath: path !== '/',
  };
}

/**
 * Checks whether two hosts match according to CSP host matching rules,
 * respecting label boundaries of subdomain wildcards.
 * https://w3c.github.io/webappsec-csp/#host-part-matches
 */
function hostPartMatches(
    source: SourceExpression, targetHost: string): boolean {
  const host = targetHost.toLowerCase();
  if (source.hasBareWildcard) {
    // A standalone "*" matches any host.
    return true;
  }
  if (source.hasHostWildcard) {
    // The wildcard only matches complete subdomain labels, e.g. "*.example.com"
    // matches "a.example.com" but not "notexample.com" or the bare
    // "example.com" (the wildcard stands for at least one full label).
    return host.endsWith('.' + source.wildcardFreeHost);
  }
  return host === source.host;
}

/**
 * Checks whether the scheme of a source expression covers the scheme of a
 * target URL. Scheme-relative sources ("//host") match any scheme.
 * https://w3c.github.io/webappsec-csp/#scheme-part-matches
 */
function schemePartMatches(
    source: SourceExpression, target: SourceExpression): boolean {
  if (source.scheme === '') {
    // At least one side is scheme relative and therefore does not impose a
    // scheme restriction on the match.
    return true;
  }
  const targetScheme = target.scheme || target.url.protocol;
  if (source.scheme === targetScheme) {
    return true;
  }
  // Browsers allow secure upgrades of explicitly insecure schemes:
  // http: also matches https:, ws: also matches http(s):/wss:.
  if (source.scheme === 'http:' && targetScheme === 'https:') {
    return true;
  }
  if (source.scheme === 'ws:' &&
      (targetScheme === 'wss:' || targetScheme === 'http:' ||
       targetScheme === 'https:')) {
    return true;
  }
  return false;
}

/**
 * Checks whether the port of a source expression covers the port of a target
 * URL, comparing effective (default-port aware) ports.
 * https://w3c.github.io/webappsec-csp/#port-part-matches
 */
function portPartMatches(
    source: SourceExpression, target: SourceExpression): boolean {
  if (source.hasPortWildcard) {
    return true;
  }
  // https://w3c.github.io/webappsec-csp/#port-part-matching
  // The target's effective port is its explicit port or the default port of
  // its scheme. A source without an explicit port is normalized the same way;
  // scheme-relative sources and secure upgrades resolve against the target
  // scheme, hence they use the target's effective port.
  const targetScheme = target.scheme || target.url.protocol;
  const targetPort = target.port ?? DEFAULT_PORTS.get(targetScheme) ?? null;
  if (targetPort === null) {
    return false;
  }

  if (source.port !== null) {
    return source.port === targetPort;
  }

  const resolvesAgainstTargetScheme = source.scheme === '' ||
      (source.scheme === 'http:' && targetScheme === 'https:') ||
      (source.scheme === 'ws:' &&
       (targetScheme === 'https:' || targetScheme === 'wss:'));
  if (resolvesAgainstTargetScheme) {
    return true;
  }

  return DEFAULT_PORTS.get(source.scheme) === targetPort;
}

/**
 * Checks whether the path of a source expression covers the path of a target
 * URL. An empty path matches everything; a path ending in "/" matches every
 * path beneath it while any other path requires an exact segment match.
 * https://w3c.github.io/webappsec-csp/#path-part-matches
 */
function safeDecodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    // Keep the raw segment if it contains malformed percent encoding.
    return segment;
  }
}

function pathPartMatches(
    source: SourceExpression, target: SourceExpression): boolean {
  if (!source.hasPath) {
    return true;
  }
  // https://w3c.github.io/webappsec-csp/#path-part-matching
  // Paths are compared segment by segment (split on "/"). A path ending in "/"
  // matches every path beneath it; any other path requires an exact segment
  // match. Percent-encoding differences are normalized while comparing.
  const exactMatch = !source.path.endsWith('/');
  const sourceSegments = source.path.split('/');
  const targetSegments = target.path.split('/');
  // Every absolute path starts with an empty segment (the text before its
  // leading "/"), which is identical on both sides and ignored here.
  const sourceSegmentCount = sourceSegments.length - 1;
  const targetSegmentCount = targetSegments.length - 1;

  if (sourceSegmentCount > targetSegmentCount) {
    return false;
  }
  if (exactMatch && sourceSegmentCount !== targetSegmentCount) {
    return false;
  }

  const compareLength =
      exactMatch ? sourceSegments.length : sourceSegments.length - 1;
  for (let i = 0; i < compareLength; i++) {
    if (safeDecodePathSegment(sourceSegments[i]) !==
        safeDecodePathSegment(targetSegments[i])) {
      return false;
    }
  }
  return true;
}

/**
 * Searches for allowlisted CSP origin (URL with wildcards) in list of urls.
 * @param cspUrlString The allowlisted CSP origin. Can contain domain and
 *   path wildcards.
 * @param listOfUrlStrings List of urls to search in.
 * @return First match found in url list, null otherwise.
 */
export function matchWildcardUrls(
    cspUrlString: string, listOfUrlStrings: string[]): URL|null {
  const source = parseSourceExpression(cspUrlString);
  if (source === null) {
    return null;
  }

  for (const urlString of listOfUrlStrings) {
    const target = parseSourceExpression(urlString);
    if (target === null) {
      continue;
    }

    // All parts of the source expression have to match together; a mismatch in
    // any single part prevents the whole expression from matching.
    if (!schemePartMatches(source, target) ||
        !hostPartMatches(source, target.host) ||
        !portPartMatches(source, target) ||
        !pathPartMatches(source, target)) {
      continue;
    }

    // We found a match. Return the parsed bypass URL, preserving its original
    // components (credentials, IPv6 host and port evidence).
    return target.url;
  }

  // No match was found.
  return null;
}


/**
 * Applies a check to all directive values of a csp.
 * @param parsedCsp Parsed CSP.
 * @param check The check function that
 *   should get applied on directive values.
 */
export function applyCheckFunktionToDirectives(
    parsedCsp: csp.Csp,
    check: (directive: string, directiveValues: string[]) => void,
) {
  const directiveNames = Object.keys(parsedCsp.directives);

  for (const directive of directiveNames) {
    const directiveValues = parsedCsp.directives[directive];
    if (directiveValues) {
      check(directive, directiveValues);
    }
  }
}
