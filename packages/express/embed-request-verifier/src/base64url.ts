// Copyright (c) 2014, Joaquim José F. Serafim
// source https://github.com/joaquimserafim/base64-url/blob/master/index.js
export function unescape(str: string): string {
  return (str + "===".slice((str.length + 3) % 4)).replace(/-/g, "+").replace(/_/g, "/");
}
