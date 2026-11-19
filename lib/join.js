// What /join tells people to add to their Reticulum config, and the QR code of it. The same text is
// in public/join.html; test/join.test.js checks that the two agree.
import { encode, toSvg } from './qr.js';

export const JOIN_HOST = 'rns.rettui.dev';
export const JOIN_PORT = 4242;

// One interface, to go below the [interfaces] line of an existing config. The name is the
// section title; Reticulum has no "name" setting.
export const JOIN_SNIPPET = `  [[rettui entry point]]
    type = TCPClientInterface
    enabled = yes
    target_host = ${JOIN_HOST}
    target_port = ${JOIN_PORT}
`;

// Made once: the text never changes while the server runs.
let svg = null;
export function joinQrSvg() {
  svg ??= toSvg(encode(JOIN_SNIPPET, { level: 'M' }).grid);
  return svg;
}
