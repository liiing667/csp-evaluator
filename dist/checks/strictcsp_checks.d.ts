import * as csp from '../csp';
import { Csp } from '../csp';
import { Finding } from '../finding';
export declare function checkStrictDynamic(parsedCsp: Csp): Finding[];
export declare function checkStrictDynamicNotStandalone(parsedCsp: Csp): Finding[];
export declare function checkUnsafeInlineFallback(parsedCsp: Csp): Finding[];
export declare function checkAllowlistFallback(parsedCsp: Csp): Finding[];
export declare function checkRequiresTrustedTypesForScripts(parsedCsp: Csp): Finding[];
export declare function checkTrustedTypesPolicy(parsedCsp: Csp, cspVersion?: csp.Version): Finding[];
//# sourceMappingURL=strictcsp_checks.d.ts.map