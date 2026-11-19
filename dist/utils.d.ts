import * as csp from './csp';
export declare function getSchemeFreeUrl(url: string): string;
export declare function getHostname(url: string): string;
export interface SourceExpression {
    url: URL;
    scheme: string;
    host: string;
    wildcardFreeHost: string;
    hasHostWildcard: boolean;
    hasBareWildcard: boolean;
    port: number | null;
    hasPortWildcard: boolean;
    path: string;
    hasPath: boolean;
}
export declare function parseSourceExpression(expression: string): SourceExpression | null;
export declare function matchWildcardUrls(cspUrlString: string, listOfUrlStrings: string[]): URL | null;
export declare function applyCheckFunktionToDirectives(parsedCsp: csp.Csp, check: (directive: string, directiveValues: string[]) => void): void;
//# sourceMappingURL=utils.d.ts.map