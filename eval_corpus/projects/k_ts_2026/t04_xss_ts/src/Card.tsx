import React from "react";

export function Card({ html }: { html: string }) {
  const params = new URLSearchParams(window.location.search);
  const note = params.get("note") ?? "";
  return <div dangerouslySetInnerHTML={{ __html: note }} />;
}
