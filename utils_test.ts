/**
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
 *
 * @author lwe@google.com (Lukas Weichselbaum)
 */

import 'jasmine';

import {getHostname, getSchemeFreeUrl, matchWildcardUrls,
        parseSourceExpression} from './utils';

const TEST_BYPASSES = [
  'https://googletagmanager.com/gtm/js', 'https://www.google.com/jsapi',
  'https://ajax.googleapis.com/ajax/services/feed/load'
];

describe('Test Utils', () => {
  it('GetSchemeFreeUrl', () => {
    expect(getSchemeFreeUrl('https://*')).toBe('*');
    expect(getSchemeFreeUrl('//*')).toBe('*');
    expect(getSchemeFreeUrl('*')).toBe('*');
    expect(getSchemeFreeUrl('test//*')).toBe('test//*');
  });

  it('MatchWildcardUrlsMatchWildcardFreeHost', () => {
    const wildcardFreeHost = '//www.google.com';
    const match = matchWildcardUrls(wildcardFreeHost, TEST_BYPASSES);
    expect(match!.hostname).toBe('www.google.com');
  });

  it('MatchWildcardUrlsNoMatch', () => {
    const wildcardFreeHost = '//www.foo.bar';
    const match = matchWildcardUrls(wildcardFreeHost, TEST_BYPASSES);
    expect(match).toBeNull();
  });

  it('MatchWildcardUrlsMatchWildcardHost', () => {
    const wildcardHost = '//*.google.com';
    const match = matchWildcardUrls(wildcardHost, TEST_BYPASSES);
    expect(match!.hostname).toBe('www.google.com');
  });

  it('MatchWildcardUrlsNoMatchWildcardHost', () => {
    const wildcardHost = '//*.www.google.com';
    const match = matchWildcardUrls(wildcardHost, TEST_BYPASSES);
    expect(match).toBeNull();
  });

  it('MatchWildcardUrlsMatchWildcardHostWithPath', () => {
    const wildcardHostWithPath = '//*.google.com/jsapi';
    const match = matchWildcardUrls(wildcardHostWithPath, TEST_BYPASSES);
    expect(match!.hostname).toBe('www.google.com');
  });

  it('MatchWildcardUrlsNoMatchWildcardHostWithPath', () => {
    const wildcardHostWithPath = '//*.google.com/wrongPath';
    const match = matchWildcardUrls(wildcardHostWithPath, TEST_BYPASSES);
    expect(match).toBeNull();
  });

  it('MatchWildcardUrlsMatchHostWithPathWildcard', () => {
    const hostWithPath = '//ajax.googleapis.com/ajax/';
    const match = matchWildcardUrls(hostWithPath, TEST_BYPASSES);
    expect(match!.hostname).toBe('ajax.googleapis.com');
  });

  it('MatchWildcardUrlsPathMatchingFollowsPathPartSemantics', () => {
    // A path without a trailing slash requires an exact path match.
    expect(matchWildcardUrls(
               '//ajax.googleapis.com/ajax',
               TEST_BYPASSES))
        .toBeNull();
    // It matches when the endpoint path is identical.
    expect(matchWildcardUrls(
               '//www.google.com/jsapi',
               TEST_BYPASSES)!.hostname)
        .toBe('www.google.com');
    // A trailing slash matches paths beneath the directory, but only across
    // path segment boundaries.
    expect(matchWildcardUrls(
               '//ajax.googleapis.com/ajax/',
               TEST_BYPASSES)!.hostname)
        .toBe('ajax.googleapis.com');
    expect(matchWildcardUrls(
               '//ajax.googleapis.com/ajax-services/',
               TEST_BYPASSES))
        .toBeNull();
  });

  it('MatchWildcardUrlsSchemeIsMatched', () => {
    // https does not match an http endpoint (no downgrade).
    expect(matchWildcardUrls(
               'https://www.google.com',
               ['http://www.google.com/jsapi']))
        .toBeNull();
    // http allows secure upgrades to https.
    expect(matchWildcardUrls(
               'http://www.google.com',
               ['https://www.google.com/jsapi'])!.hostname)
        .toBe('www.google.com');
  });

  it('MatchWildcardUrlsSchemeRelativeSourceMatchesAnyScheme', () => {
    expect(matchWildcardUrls(
               '//www.google.com',
               ['http://www.google.com/jsapi'])!.hostname)
        .toBe('www.google.com');
    expect(matchWildcardUrls(
               '//www.google.com',
               ['https://www.google.com/jsapi'])!.hostname)
        .toBe('www.google.com');
  });

  it('MatchWildcardUrlsPortIsMatched', () => {
    // An explicit port must match the endpoint's port (default aware).
    expect(matchWildcardUrls(
               '//www.google.com:8443',
               ['https://www.google.com/jsapi']))
        .toBeNull();
    expect(matchWildcardUrls(
               '//www.google.com:443',
               ['https://www.google.com/jsapi'])!.hostname)
        .toBe('www.google.com');
    expect(matchWildcardUrls(
               'https://www.google.com:8443',
               ['https://www.google.com:8443/jsapi'])!.hostname)
        .toBe('www.google.com');
  });

  it('MatchWildcardUrlsWildcardPortMatchesAnyPort', () => {
    expect(matchWildcardUrls(
               '//www.google.com:*',
               ['https://www.google.com:8443/jsapi'])!.hostname)
        .toBe('www.google.com');
  });

  it('MatchWildcardUrlsWildcardIsLabelBounded', () => {
    // "*.google.com" must not match the bare "google.com" label.
    expect(matchWildcardUrls(
               '//*.google.com',
               ['https://google.com/jsapi']))
        .toBeNull();
    // And it must not match a host that merely ends with the same string.
    expect(matchWildcardUrls(
               '//*.google.com',
               ['https://evilgoogle.com/jsapi']))
        .toBeNull();
  });

  it('MatchWildcardUrlsBareWildcardHostMatchesAnyHost', () => {
    expect(matchWildcardUrls(
               '//*',
               ['https://www.google.com/jsapi'])!.hostname)
        .toBe('www.google.com');
  });

  it('MatchWildcardUrlsPreservesCredentialsAndIpv6AndPortEvidence', () => {
    const match = matchWildcardUrls(
        'https://user:secret@[2001:db8::1]:8443',
        ['https://user:secret@[2001:db8::1]:8443/endpoint.js']);
    expect(match).not.toBeNull();
    expect(match!.hostname).toBe('[2001:db8::1]');
    expect(match!.port).toBe('8443');
    expect(match!.username).toBe('user');
    expect(match!.password).toBe('secret');
    expect(match!.pathname).toBe('/endpoint.js');
  });

  it('MatchWildcardUrlsAllPartsMustMatchTogether', () => {
    // Host matches but port does not: no match, the endpoint is not allowed.
    expect(matchWildcardUrls(
               'https://*.google.com:9000',
               ['https://www.google.com/jsapi']))
        .toBeNull();
    // Host and port match but path does not.
    expect(matchWildcardUrls(
               'https://*.google.com/other',
               ['https://www.google.com/jsapi']))
        .toBeNull();
  });

  it('ParseSourceExpressionReturnsNullForUnparsableInput', () => {
    expect(parseSourceExpression('://not a url')).toBeNull();
  });

  it('GetHostname', () => {
    expect(getHostname('https://www.google.com')).toBe('www.google.com');
  });

  it('GetHostnamePort', () => {
    expect(getHostname('https://www.google.com:8080')).toBe('www.google.com');
  });

  it('GetHostnameWildcardPort', () => {
    expect(getHostname('https://www.google.com:*')).toBe('www.google.com');
  });

  it('GetHostnameNoProtocol', () => {
    expect(getHostname('www.google.com')).toBe('www.google.com');
  });

  it('GetHostnameDoubleSlashProtocol', () => {
    expect(getHostname('//www.google.com')).toBe('www.google.com');
  });

  it('GetHostnameWildcard', () => {
    expect(getHostname('//*.google.com')).toBe('*.google.com');
  });

  it('GetHostnameWithPath', () => {
    expect(getHostname('//*.google.com/any/path')).toBe('*.google.com');
  });

  it('GetHostnameJustWildcard', () => {
    expect(getHostname('*')).toBe('*');
  });

  it('GetHostnameWildcardWithProtocol', () => {
    expect(getHostname('https://*')).toBe('*');
  });

  it('GetHostnameNonsense', () => {
    expect(getHostname('unsafe-inline')).toBe('unsafe-inline');
  });

  it('GetHostnameIPv4', () => {
    expect(getHostname('1.2.3.4')).toBe('1.2.3.4');
  });

  it('GetHostnameIPv6', () => {
    expect(getHostname('[::1]')).toBe('[::1]');
  });

  it('GetHostnameIPv4WithFullProtocol', () => {
    expect(getHostname('https://1.2.3.4')).toBe('1.2.3.4');
  });

  it('GetHostnameIPv6WithFullProtocol', () => {
    expect(getHostname('http://[::1]')).toBe('[::1]');
  });

  it('GetHostnameIPv4WithPartialProtocol', () => {
    expect(getHostname('//1.2.3.4')).toBe('1.2.3.4');
  });

  it('GetHostnameIPv6WithPartialProtocol', () => {
    expect(getHostname('//[::1]')).toBe('[::1]');
  });
});
