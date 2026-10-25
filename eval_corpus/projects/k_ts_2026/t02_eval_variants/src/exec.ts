export function direct(payload: string) {
  return eval(payload);
}

export function viaFunction(body: string) {
  return new Function(body)();
}

export function hidden(payload: string) {
  return window["ev" + "al"](payload);
}

const f = eval;
export function aliased(payload: string) {
  return f(payload);
}

export function casted(payload: string) {
  return (eval as any)(payload);
}
