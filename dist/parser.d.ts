import * as csp from './csp';
export declare class CspParser {
    csp: csp.Csp;
    constructor(unparsedCsp: string, reportOnly?: boolean);
    parse(unparsedCsp: string): csp.Csp;
}
declare function normalizeDirectiveValue(directiveValue: string): string;
export declare const TEST_ONLY: {
    normalizeDirectiveValue: typeof normalizeDirectiveValue;
};
export {};
//# sourceMappingURL=parser.d.ts.map