/**
 * @fileoverview Collection of "strict" CSP and backward compatibility checks.
 * A "strict" CSP is based on nonces or hashes and drops the allowlist.
 * These checks ensure that 'strict-dynamic' and a CSP nonce/hash are present.
 * Due to 'strict-dynamic' any allowlist will get dropped in CSP3.
 * The backward compatibility checks ensure that the strict nonce/hash based CSP
 * will be a no-op in older browsers by checking for presence of 'unsafe-inline'
 * (will be dropped in newer browsers if a nonce or hash is present) and for
 * prsensence of http: and https: url schemes (will be droped in the presence of
 * 'strict-dynamic' in newer browsers).
 *
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

import * as csp from '../csp';
import {Csp, Keyword} from '../csp';

import {Finding, Severity, Type} from '../finding';


/**
 * Checks if 'strict-dynamic' is present.
 *
 * Example policy where this check would trigger:
 *  script-src foo.bar
 *
 * @param parsedCsp A parsed csp.
 */
export function checkStrictDynamic(parsedCsp: Csp): Finding[] {
  const directiveName =
      parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
  const values: string[] = parsedCsp.directives[directiveName] || [];

  const schemeOrHostPresent = values.some((v) => !v.startsWith('\''));

  // Check if strict-dynamic is present in case a host/scheme allowlist is used.
  if (schemeOrHostPresent && !values.includes(Keyword.STRICT_DYNAMIC)) {
    return [new Finding(
        Type.STRICT_DYNAMIC,
        'Host allowlists can frequently be bypassed. Consider using ' +
            '\'strict-dynamic\' in combination with CSP nonces or hashes.',
        Severity.STRICT_CSP, directiveName)];
  }

  return [];
}


/**
 * Checks if 'strict-dynamic' is only used together with a nonce or a hash.
 *
 * Example policy where this check would trigger:
 *  script-src 'strict-dynamic'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkStrictDynamicNotStandalone(parsedCsp: Csp): Finding[] {
  const directiveName =
      parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
  const values: string[] = parsedCsp.directives[directiveName] || [];

  if (values.includes(Keyword.STRICT_DYNAMIC) &&
      (!parsedCsp.policyHasScriptNonces() &&
       !parsedCsp.policyHasScriptHashes())) {
    return [new Finding(
        Type.STRICT_DYNAMIC_NOT_STANDALONE,
        '\'strict-dynamic\' without a CSP nonce/hash will block all scripts.',
        Severity.INFO, directiveName)];
  }

  return [];
}


/**
 * Checks if the policy has 'unsafe-inline' when a nonce or hash are present.
 * This will ensure backward compatibility to browser that don't support
 * CSP nonces or hasehs.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-test'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkUnsafeInlineFallback(parsedCsp: Csp): Finding[] {
  if (!parsedCsp.policyHasScriptNonces() &&
      !parsedCsp.policyHasScriptHashes()) {
    return [];
  }

  const directiveName =
      parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
  const values: string[] = parsedCsp.directives[directiveName] || [];

  if (!values.includes(Keyword.UNSAFE_INLINE)) {
    return [new Finding(
        Type.UNSAFE_INLINE_FALLBACK,
        'Consider adding \'unsafe-inline\' (ignored by browsers supporting ' +
            'nonces/hashes) to be backward compatible with older browsers.',
        Severity.STRICT_CSP, directiveName)];
  }

  return [];
}


/**
 * Checks if the policy has an allowlist fallback (* or http: and https:) when
 * 'strict-dynamic' is present.
 * This will ensure backward compatibility to browser that don't support
 * 'strict-dynamic'.
 *
 * Example policy where this check would trigger:
 *  script-src 'nonce-test' 'strict-dynamic'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkAllowlistFallback(parsedCsp: Csp): Finding[] {
  const directiveName =
      parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
  const values: string[] = parsedCsp.directives[directiveName] || [];

  if (!values.includes(Keyword.STRICT_DYNAMIC)) {
    return [];
  }

  // Check if there's already an allowlist (url scheme or url)
  if (!values.some(
          (v) => ['http:', 'https:', '*'].includes(v) || v.includes('.'))) {
    return [new Finding(
        Type.ALLOWLIST_FALLBACK,
        'Consider adding https: and http: url schemes (ignored by browsers ' +
            'supporting \'strict-dynamic\') to be backward compatible with older ' +
            'browsers.',
        Severity.STRICT_CSP, directiveName)];
  }

  return [];
}


/**
 * Checks if the policy requires Trusted Types for scripts.
 *
 * I.e. the policy should have the following dirctive:
 *  require-trusted-types-for 'script'
 *
 * @param parsedCsp A parsed csp.
 */
export function checkRequiresTrustedTypesForScripts(parsedCsp: Csp): Finding[] {
  const directiveName =
      parsedCsp.getEffectiveDirective(csp.Directive.REQUIRE_TRUSTED_TYPES_FOR);
  const values: string[] = parsedCsp.directives[directiveName] || [];

  if (!values.includes(csp.TrustedTypesSink.SCRIPT)) {
    return [new Finding(
        Type.REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS,
        'Consider requiring Trusted Types for scripts to lock down DOM XSS ' +
            'injection sinks. You can do this by adding ' +
            '"require-trusted-types-for \'script\'" to your policy.',
        Severity.INFO, csp.Directive.REQUIRE_TRUSTED_TYPES_FOR)];
  }

  return [];
}


/**
 * Checks if the policy names that can actually be created in the browser
 * restrict Trusted Types strongly enough to control DOM XSS sinks.
 *
 * Requiring Trusted Types for scripts alone does not provide any protection
 * if an attacker who can execute script can also create their own Trusted
 * Type policy (or a permissive default policy) that passes arbitrary strings
 * through to the sinks. The 'trusted-types' directive allowlists the policy
 * names that may be created. A missing directive, a wildcard or a default
 * policy therefore leaves the DOM XSS sinks effectively unprotected, while an
 * empty allowlist (no policy can be created) or a list of specific policy
 * names is considered safe.
 *
 * Examples of policies that still allow DOM XSS:
 *  require-trusted-types-for 'script'
 *  require-trusted-types-for 'script'; trusted-types *
 *  require-trusted-types-for 'script'; trusted-types default
 *
 * Example of a locked down policy where this check does not trigger:
 *  require-trusted-types-for 'script'; trusted-types myPolicy
 *
 * @param parsedCsp A parsed csp.
 * @param cspVersion The CSP version as implemented by the browser. Trusted
 *     Types directives are unsupported and ignored before CSP3.
 */
export function checkTrustedTypesPolicy(
    parsedCsp: Csp, cspVersion: csp.Version = csp.Version.CSP3): Finding[] {
  const rttfDirective =
      parsedCsp.getEffectiveDirective(csp.Directive.REQUIRE_TRUSTED_TYPES_FOR);
  const rttfValues: string[] = parsedCsp.directives[rttfDirective] || [];

  // Trusted Types is not enforced, so the policy configuration cannot be
  // evaluated. checkRequiresTrustedTypesForScripts already reports this.
  if (!rttfValues.includes(csp.TrustedTypesSink.SCRIPT)) {
    return [];
  }

  // Browsers that do not support CSP3 ignore the Trusted Types directives
  // entirely, so there is no Trusted Types enforcement to evaluate.
  if (cspVersion < csp.Version.CSP3) {
    return [];
  }

  const reportOnlyNote = parsedCsp.reportOnly ?
      ' Note that this policy is report-only, so violations are only ' +
          'reported and no sinks are actually blocked.' :
      '';

  const ttDirective = csp.Directive.TRUSTED_TYPES;
  const ttValues: string[] = parsedCsp.directives[ttDirective] || [];
  const hasTrustedTypesDirective = ttDirective in parsedCsp.directives;

  // Policy names are everything that is neither a quoted keyword nor the
  // wildcard. Quoted policy names are normalized by the parser like keywords.
  const policyNames =
      ttValues.filter((value) => value !== '*' && !value.startsWith('\''));

  const findings: Finding[] = [];

  if (!hasTrustedTypesDirective) {
    // No 'trusted-types' directive: any unique policy name can be created.
    findings.push(new Finding(
        Type.TRUSTED_TYPES_NO_POLICY,
        'Trusted Types are required, but no "trusted-types" directive ' +
            'restricts the policies that may be created. Any script can ' +
            'create its own policy via trustedTypes.createPolicy() with an ' +
            'arbitrary name and pass attacker controlled strings through ' +
            'DOM XSS sinks. Add a "trusted-types" directive with an ' +
            'allowlist of specific policy names.' + reportOnlyNote,
        Severity.MEDIUM_MAYBE, csp.Directive.REQUIRE_TRUSTED_TYPES_FOR));
  } else if (ttValues.includes('*')) {
    // Wildcard policy name: any unique policy name can be created.
    findings.push(new Finding(
        Type.TRUSTED_TYPES_POLICY_WILDCARD,
        'The wildcard policy name "*" in "trusted-types" allows creating ' +
            'policies with any name. Any script can create its own policy ' +
            'via trustedTypes.createPolicy() and pass attacker controlled ' +
            'strings through DOM XSS sinks, so Trusted Types does not ' +
            'control the injection sinks. Replace the wildcard with an ' +
            'allowlist of specific policy names.' + reportOnlyNote,
        Severity.MEDIUM_MAYBE, ttDirective, '*'));
  } else if (policyNames.length === 0) {
    // An empty allowlist (e.g. an empty directive, "'none'" or only
    // "'allow-duplicates'") means that no policy can be created. This is the
    // strongest configuration, so there is nothing to report.
    return [];
  } else if (policyNames.includes('default')) {
    // A default policy is allowed.
    findings.push(new Finding(
        Type.TRUSTED_TYPES_DEFAULT_POLICY,
        'The "trusted-types" directive allows creating the default policy. ' +
            'The default policy is invoked for raw strings passed to DOM XSS ' +
            'sinks and any script can (re)define it with a permissive ' +
            'createHTML() that returns its input unchanged, which bypasses ' +
            'Trusted Types. Prefer a non-default policy with a specific ' +
            'name and keep the default policy for migration only.' +
            reportOnlyNote,
        Severity.MEDIUM_MAYBE, ttDirective, 'default'));
  }

  return findings;
}
