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

import {Finding, Severity, Type} from '../finding';
import {CspParser} from '../parser';

import {CheckerFunction} from './checker';
import * as strictcspChecks from './strictcsp_checks';


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

  /** Tests for strictcspChecks.checkTrustedTypesPolicy */
  it('CheckTrustedTypesPolicyDoesntFireWithoutTrustedTypes', () => {
    const test = 'script-src \'nonce-test\'';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyDoesntFireIfTrustedTypesNotRequired', () => {
    const test = 'trusted-types *';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyDoesntFireForSpecificPolicyName', () => {
    const test = 'require-trusted-types-for \'script\'; trusted-types myPolicy';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyDoesntFireForMultipleSpecificPolicyNames', () => {
    const test =
        'require-trusted-types-for \'script\'; trusted-types policy1 policy2 ' +
        '\'allow-duplicates\'';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyDoesntFireForEmptyAllowlist', () => {
    const test = 'require-trusted-types-for \'script\'; trusted-types';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyDoesntFireForNoneKeyword', () => {
    const test =
        'require-trusted-types-for \'script\'; trusted-types \'none\'';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyDoesntFireForAllowDuplicatesOnly', () => {
    const test = 'require-trusted-types-for \'script\'; trusted-types ' +
        '\'allow-duplicates\'';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(0);
  });

  it('CheckTrustedTypesPolicyFiresWithoutTrustedTypesDirective', () => {
    const test = 'require-trusted-types-for \'script\'';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(1);
    expect(violations[0].type).toBe(Type.TRUSTED_TYPES_NO_POLICY);
    expect(violations[0].severity).toBe(Severity.MEDIUM_MAYBE);
  });

  it('CheckTrustedTypesPolicyFiresForWildcardPolicyName', () => {
    const test = 'require-trusted-types-for \'script\'; trusted-types *';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(1);
    expect(violations[0].type).toBe(Type.TRUSTED_TYPES_POLICY_WILDCARD);
    expect(violations[0].severity).toBe(Severity.MEDIUM_MAYBE);
    expect(violations[0].value).toBe('*');
    expect(violations[0].directive).toBe('trusted-types');
  });

  it('CheckTrustedTypesPolicyFiresForDefaultPolicy', () => {
    const test =
        'require-trusted-types-for \'script\'; trusted-types default';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(1);
    expect(violations[0].type).toBe(Type.TRUSTED_TYPES_DEFAULT_POLICY);
    expect(violations[0].severity).toBe(Severity.MEDIUM_MAYBE);
    expect(violations[0].value).toBe('default');
  });

  it('CheckTrustedTypesPolicyFiresForDefaultPolicyAlongsideAnotherPolicy',
     () => {
       const test = 'require-trusted-types-for \'script\'; trusted-types ' +
           'myPolicy default';

       const violations =
           checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
       expect(violations.length).toBe(1);
       expect(violations[0].type).toBe(Type.TRUSTED_TYPES_DEFAULT_POLICY);
     });

  it('CheckTrustedTypesPolicyReportsReportOnlyMode', () => {
    const test = 'require-trusted-types-for \'script\'; trusted-types *';
    const parsedCsp = (new CspParser(test, true)).csp;

    expect(parsedCsp.reportOnly).toBe(true);
    const violations = strictcspChecks.checkTrustedTypesPolicy(parsedCsp);
    expect(violations.length).toBe(1);
    expect(violations[0].description).toContain('report-only');
  });

  it('CheckTrustedTypesPolicyDoesNotMentionReportOnlyInEnforceMode', () => {
    const test = 'require-trusted-types-for \'script\'; trusted-types *';

    const violations = checkCsp(test, strictcspChecks.checkTrustedTypesPolicy);
    expect(violations.length).toBe(1);
    expect(violations[0].description).not.toContain('report-only');
  });
});
