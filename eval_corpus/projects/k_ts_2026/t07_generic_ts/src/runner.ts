export function run<T extends string>(expr: T): unknown {
  return eval(expr as unknown as string);
}

export const lazy = <T,>(x: T) => (eval as (s: string) => unknown)(String(x));
