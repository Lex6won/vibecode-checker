declare module "legacy-calc" {
  export function evaluate(expr: string): number;
  export function query(sql: string, params: unknown[]): Promise<unknown[]>;
}
