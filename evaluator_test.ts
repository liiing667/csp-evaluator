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

  it('EvaluateSurfacesHighRiskFromOldCspVersions', () => {
    // 'unsafe-inline' is ignored in the presence of a nonce in CSP2 and
    // above, but CSP1 browsers don't know nonces and will execute inline
    // scripts. The high risk finding of the old browser's effective policy
    // must show up in the evaluation.
    const testCsp = 'default-src \'none\'; ' +
        'script-src \'nonce-12345678\' \'unsafe-inline\'; ' +
        'object-src \'none\'; base-uri \'none\';';
    const parsed = (new CspParser(testCsp)).csp;

    const findings = (new CspEvaluator(parsed)).evaluate();

    const unsafeInlineFindings = findings.filter(
        (finding) => finding.type === Type.SCRIPT_UNSAFE_INLINE &&
            finding.severity === Severity.HIGH);
    expect(unsafeInlineFindings.length).toBe(1);
  });

  it('EvaluateStrictPolicyStaysClean', () => {
    // A strict nonce based policy is effective in all CSP versions and must
    // not produce high severity findings.
    const testCsp = 'default-src \'none\'; ' +
        'script-src \'nonce-12345678\' \'strict-dynamic\'; ' +
        'object-src \'none\'; base-uri \'none\';';
    const parsed = (new CspParser(testCsp)).csp;

    const findings = (new CspEvaluator(parsed)).evaluate();

    expect(findings.filter((finding) => finding.severity === Severity.HIGH))
        .toEqual([]);
  });

  it('EvaluateRespectsConfiguredVersion', () => {
    // The policy is evaluated as seen by browsers supporting all CSP versions
    // up to the configured one.
    const testCsp = 'script-src \'nonce-12345678\' \'unsafe-inline\'';
    const parsed = (new CspParser(testCsp)).csp;

    const evaluatedVersions: Array<Version|undefined> = [];
    const recordVersion = (effectiveCsp: Csp) => {
      evaluatedVersions.push(effectiveCsp.version);
      return [];
    };

    (new CspEvaluator(parsed, Version.CSP1)).evaluate(undefined, [
      recordVersion
    ]);
    expect(evaluatedVersions).toEqual([Version.CSP1]);

    evaluatedVersions.length = 0;
    (new CspEvaluator(parsed)).evaluate(undefined, [recordVersion]);
    expect(evaluatedVersions)
        .toEqual([Version.CSP1, Version.CSP2, Version.CSP3]);
  });
});
