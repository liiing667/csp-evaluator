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
 * @fileoverview Tests for CSP Evaluator.
 * @author lwe@google.com (Lukas Weichselbaum)
 */

import 'jasmine';

import {Csp, Version} from './csp';
import {CspEvaluator} from './evaluator';
import {Finding, Severity, Type} from './finding';
import {CspParser} from './parser';
import {STRICTCSP_CHECKS} from './evaluator';

function evaluateStrictCsp(csp: string, version?: Version,
                           reportOnly = false): Finding[] {
  const parsedCsp = new CspParser(csp, reportOnly).csp;
  return new CspEvaluator(parsedCsp, version).evaluate(STRICTCSP_CHECKS);
}

describe('Test evaluator', () => {
  it('CspEvaluator', () => {
    const fakeCsp = new Csp();
    const evaluator = new CspEvaluator(fakeCsp);
    expect(evaluator.csp).toBe(fakeCsp);
  });

  it('Evaluate', () => {
    const fakeCsp = new (Csp)();
    const fakeFinding = new (Finding)(
        Type.UNKNOWN_DIRECTIVE, 'Fake description', Severity.MEDIUM,
        'fake-directive', 'fake-directive-value');
    const fakeVerifier = (parsedCsp: Csp) => {
      return [fakeFinding];
    };

    const evaluator = new (CspEvaluator)(fakeCsp);
    const findings =
        evaluator.evaluate([fakeVerifier, fakeVerifier], [fakeVerifier]);

    const expectedFindings = [fakeFinding, fakeFinding, fakeFinding];
    expect(findings).toEqual(expectedFindings);
  });

  it('StrictNoncePolicyWithNamedTrustedTypesPolicyStaysClean', () => {
    const csp = 'script-src \'nonce-abc123def456\' \'strict-dynamic\' ' +
        '\'unsafe-inline\' https: http:; object-src \'none\'; ' +
        'base-uri \'none\'; require-trusted-types-for \'script\'; ' +
        'trusted-types myPolicy';

    const findings = evaluateStrictCsp(csp);
    const ttFindings = findings.filter(
        (finding) => finding.type === Type.TRUSTED_TYPES_NO_POLICY ||
            finding.type === Type.TRUSTED_TYPES_POLICY_WILDCARD ||
            finding.type === Type.TRUSTED_TYPES_DEFAULT_POLICY);
    expect(ttFindings.length).toBe(0);
  });

  it('WildcardTrustedTypesPolicyShowsBypassEvidence', () => {
    const csp = 'script-src \'nonce-abc123def456\'; ' +
        'require-trusted-types-for \'script\'; trusted-types *';

    const findings = evaluateStrictCsp(csp);
    const ttFinding =
        findings.find((finding) =>
                          finding.type === Type.TRUSTED_TYPES_POLICY_WILDCARD);
    expect(ttFinding).toBeDefined();
    expect(ttFinding?.severity).toBe(Severity.MEDIUM_MAYBE);
    expect(ttFinding?.description)
        .toContain('trustedTypes.createPolicy()');
  });

  it('MissingTrustedTypesDirectiveShowsBypassEvidence', () => {
    const csp = 'script-src \'nonce-abc123def456\'; ' +
        'require-trusted-types-for \'script\'';

    const findings = evaluateStrictCsp(csp);
    const ttFinding =
        findings.find((finding) =>
                          finding.type === Type.TRUSTED_TYPES_NO_POLICY);
    expect(ttFinding).toBeDefined();
  });

  it('DefaultTrustedTypesPolicyShowsBypassEvidence', () => {
    const csp = 'script-src \'nonce-abc123def456\'; ' +
        'require-trusted-types-for \'script\'; trusted-types default';

    const findings = evaluateStrictCsp(csp);
    const ttFinding =
        findings.find((finding) =>
                          finding.type === Type.TRUSTED_TYPES_DEFAULT_POLICY);
    expect(ttFinding).toBeDefined();
  });

  it('ReportOnlyPolicyMentionsThatSinksAreNotBlocked', () => {
    const csp = 'require-trusted-types-for \'script\'; trusted-types *';

    const findings = evaluateStrictCsp(csp, Version.CSP3, true);
    const ttFinding =
        findings.find((finding) =>
                          finding.type === Type.TRUSTED_TYPES_POLICY_WILDCARD);
    expect(ttFinding?.description).toContain('report-only');
  });

  it('TrustedTypesCheckIsSkippedForPreCsp3Browsers', () => {
    const csp = 'require-trusted-types-for \'script\'';

    const findings = evaluateStrictCsp(csp, Version.CSP2);
    const ttPolicyFindings = findings.filter(
        (finding) => finding.type === Type.TRUSTED_TYPES_NO_POLICY ||
            finding.type === Type.TRUSTED_TYPES_POLICY_WILDCARD ||
            finding.type === Type.TRUSTED_TYPES_DEFAULT_POLICY);
    expect(ttPolicyFindings.length).toBe(0);
  });
});
