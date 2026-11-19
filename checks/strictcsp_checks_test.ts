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
 * @fileoverview Tests for strict CSP checks.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

import {Finding, Severity} from '../finding';
import {CspParser} from '../parser';

import {CheckerFunction} from './checker';
import * as strictcspChecks from './strictcsp_checks';
import {Directive} from '../csp';


/**
 * Helper function for running a check on a CSP string.
 *
 * @param test CSP string.
 * @param checkFunction check.
 */
function checkCsp(test: string, checkFunction: CheckerFunction): Finding[] {
  const parsedCsp = (new CspParser(test)).csp;
  return checkFunction(parsedCsp);
}

describe('Test strictcsp checks', () => {
  /** Tests for csp.strictcspChecks.checkStrictDynamic */
  it('CheckStrictDynamic', () => {
    const test = 'script-src foo.bar';

    const violations = checkCsp(test, strictcspChecks.checkStrictDynamic);
    expect(violations.length).toBe(1);
    expect(violations[0].severity).toBe(Severity.STRICT_CSP);
  });

  it('CheckStrictDynamicEvaluatesElemAndAttrContextsIndependently', () => {
    // script-src-elem is a strict nonce + strict-dynamic policy, but the
    // bypassable script-src allowlist still governs event handlers (and is
    // the fallback for contexts not covered by script-src-elem). The
    // strict-dynamic in script-src-elem must not neutralize the script-src
    // host sources.
    const test =
        'script-src https://cdn.example.com https://apis.google.com; ' +
        'script-src-elem \'nonce-abcdef12345\' \'strict-dynamic\' ' +
        'https://cdn.example.com';

    const violations = checkCsp(test, strictcspChecks.checkStrictDynamic);
    expect(violations.length).toBe(1);
    expect(violations[0].directive).toBe(Directive.SCRIPT_SRC);
    expect(violations[0].severity).toBe(Severity.STRICT_CSP);
  });

  it('CheckStrictDynamicPassesForStrictElemAndAttrContexts', () => {
    // A fully strict split policy: no context relies on a host allowlist that
    // is not ignored by strict-dynamic.
    const test =
        'script-src \'none\'; ' +
        'script-src-elem \'nonce-abcdef12345\' \'strict-dynamic\'; ' +
        'script-src-attr \'none\'';

    const violations = checkCsp(test, strictcspChecks.checkStrictDynamic);
    expect(violations.length).toBe(0);
  });

  /** Tests for csp.strictcspChecks.checkStrictDynamicNotStandalone */
  it('CheckStrictDynamicNotStandalone', () => {
    const test = 'script-src \'strict-dynamic\'';

    const violations =
        checkCsp(test, strictcspChecks.checkStrictDynamicNotStandalone);
    expect(violations[0].severity).toBe(Severity.INFO);
  });

  it('CheckStrictDynamicNotStandaloneDoesntFireIfNoncePresent', () => {
    const test = 'script-src \'strict-dynamic\' \'nonce-foobar\'';

    const violations =
        checkCsp(test, strictcspChecks.checkStrictDynamicNotStandalone);
    expect(violations.length).toBe(0);
  });

  it('CheckStrictDynamicNotStandalonePerContext', () => {
    // strict-dynamic without a nonce/hash in script-src-elem is reported on
    // that directive; the nonce in script-src must not authorize it.
    const test =
        'script-src \'nonce-abcdef12345\'; ' +
        'script-src-elem \'strict-dynamic\'';

    const violations =
        checkCsp(test, strictcspChecks.checkStrictDynamicNotStandalone);
    expect(violations.length).toBe(1);
    expect(violations[0].directive).toBe(Directive.SCRIPT_SRC_ELEM);
    expect(violations[0].severity).toBe(Severity.INFO);
  });

  /** Tests for csp.strictcspChecks.checkUnsafeInlineFallback */
  it('CheckUnsafeInlineFallback', () => {
    const test = 'script-src \'nonce-test\'';

    const violations =
        checkCsp(test, strictcspChecks.checkUnsafeInlineFallback);
    expect(violations.length).toBe(1);
    expect(violations[0].severity).toBe(Severity.STRICT_CSP);
  });

  it('CheckUnsafeInlineFallbackDoesntFireIfFallbackPresent', () => {
    const test = 'script-src \'nonce-test\' \'unsafe-inline\'';

    const violations =
        checkCsp(test, strictcspChecks.checkUnsafeInlineFallback);
    expect(violations.length).toBe(0);
  });

  it('CheckUnsafeInlineFallbackOnlyForContextsWithNonceOrHash', () => {
    // Only script-src-elem uses a nonce, so the fallback hint must reference
    // script-src-elem and must not be emitted for the allowlist script-src.
    const test =
        'script-src https://cdn.example.com; ' +
        'script-src-elem \'nonce-abcdef12345\' \'strict-dynamic\'';

    const violations =
        checkCsp(test, strictcspChecks.checkUnsafeInlineFallback);
    expect(violations.length).toBe(1);
    expect(violations[0].directive).toBe(Directive.SCRIPT_SRC_ELEM);
  });

  /** Tests for csp.strictcspChecks.checkAllowlistFallback */
  it('checkAllowlistFallback', () => {
    const test = 'script-src \'nonce-test\' \'strict-dynamic\'';

    const violations = checkCsp(test, strictcspChecks.checkAllowlistFallback);
    expect(violations.length).toBe(1);
    expect(violations[0].severity).toBe(Severity.STRICT_CSP);
  });

  it('checkAllowlistFallbackDoesntFireIfSchemeFallbackPresent', () => {
    const test = 'script-src \'nonce-test\' \'strict-dynamic\' https:';

    const violations = checkCsp(test, strictcspChecks.checkAllowlistFallback);
    expect(violations.length).toBe(0);
  });

  it('checkAllowlistFallbackDoesntFireIfURLFallbackPresent', () => {
    const test = 'script-src \'nonce-test\' \'strict-dynamic\' foo.bar';

    const violations = checkCsp(test, strictcspChecks.checkAllowlistFallback);
    expect(violations.length).toBe(0);
  });

  it('checkAllowlistFallbackDoesntFireInAbsenceOfStrictDynamic', () => {
    const test = 'script-src \'nonce-test\'';

    const violations = checkCsp(test, strictcspChecks.checkAllowlistFallback);
    expect(violations.length).toBe(0);
  });

  it('checkAllowlistFallbackDoesNotCrossDirectiveBoundaries', () => {
    // The host allowlist in script-src is not ignored by the strict-dynamic
    // in script-src-elem, hence it cannot serve as its backward-compat
    // fallback. The missing fallback is reported on script-src-elem only.
    const test =
        'script-src https://cdn.example.com; ' +
        'script-src-elem \'nonce-abcdef12345\' \'strict-dynamic\'';

    const violations = checkCsp(test, strictcspChecks.checkAllowlistFallback);
    expect(violations.length).toBe(1);
    expect(violations[0].directive).toBe(Directive.SCRIPT_SRC_ELEM);
  });
});
