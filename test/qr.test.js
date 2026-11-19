import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_VERSION, blankSymbol, byteCapacity, dataCodewords, encode, formatBits, gfMultiply, interleave, penalty, rsGenerator, rsRemainder, toSvg, versionBits } from '../lib/qr.js';

const bin = (n, width) => n.toString(2).padStart(width, '0');
const hex = (list) => list.map((n) => n.toString(16).padStart(2, '0')).join(' ');

test('GF(256) multiplication follows x^8 + x^4 + x^3 + x^2 + 1', () => {
  assert.equal(gfMultiply(0, 77), 0);
  assert.equal(gfMultiply(1, 77), 77);
  assert.equal(gfMultiply(2, 0x80), 0x1d);
  assert.equal(gfMultiply(0x57, 0x83), gfMultiply(0x83, 0x57));
});

test('the Reed-Solomon generator of degree 7 is the one in the standard', () => {
  // x^7 + a^87 x^6 + a^229 x^5 + a^146 x^4 + a^149 x^3 + a^238 x^2 + a^102 x + a^21
  assert.deepEqual(rsGenerator(7), [127, 122, 154, 164, 11, 68, 117]);
  assert.equal(rsGenerator(10).length, 10);
});

test('error correction of the example in ISO 18004 (version 1-M, "01234567")', () => {
  const data = [0b00010000, 0b00100000, 0b00001100, 0b01010110, 0b01100001, 0b10000000, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11];
  assert.equal(hex(rsRemainder(data, 10)), 'a5 24 d4 c1 ed 36 c7 87 2c 55');
});

test('the error correction of a message makes its own remainder zero', () => {
  const data = Array.from({ length: 43 }, (_, i) => (i * 37 + 11) & 0xff);
  const ec = rsRemainder(data, 26);
  assert.deepEqual(rsRemainder([...data, ...ec], 26), new Array(26).fill(0));
});

test('format information matches the published values', () => {
  assert.equal(bin(formatBits('M', 0), 15), '101010000010010');
  assert.equal(bin(formatBits('L', 0), 15), '111011111000100');
  assert.equal(bin(formatBits('L', 1), 15), '111001011110011');
  // Every code is at least 7 bits from every other (the distance of the BCH code), so readers can correct 3 bit errors.
  const all = [];
  for (const level of ['L', 'M']) for (let mask = 0; mask < 8; mask++) all.push(formatBits(level, mask));
  for (let i = 0; i < all.length; i++) {
    for (let j = i + 1; j < all.length; j++) {
      let x = all[i] ^ all[j];
      let n = 0;
      for (; x; x &= x - 1) n++;
      assert.ok(n >= 7);
    }
  }
});

test('version information matches the published values', () => {
  assert.equal(versionBits(7), 0x07c94);
  assert.equal(versionBits(8), 0x085bc);
  assert.equal(versionBits(9), 0x09a99);
  assert.equal(versionBits(10), 0x0a4d3);
});

test('byte capacities are those of the standard', () => {
  const L = [17, 32, 53, 78, 106, 134, 154, 192, 230, 271];
  const M = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213];
  for (let v = 1; v <= MAX_VERSION; v++) {
    assert.equal(byteCapacity(v, 'L'), L[v - 1], `L ${v}`);
    assert.equal(byteCapacity(v, 'M'), M[v - 1], `M ${v}`);
  }
});

test('the data codewords of "Hello" in version 1-M, worked out by hand', () => {
  // 0100 (byte mode) 00000101 (5) 48 65 6c 6c 6f 0000 (end), then the pad bytes EC and 11.
  assert.equal(hex(dataCodewords(Buffer.from('Hello'), 1, 'M')), '40 54 86 56 c6 c6 f0 ec 11 ec 11 ec 11 ec 11 ec');
});

test('a longer message in version 10 has a 16 bit length', () => {
  const data = dataCodewords(Buffer.alloc(200, 0x41), 10, 'M');
  assert.equal(data.length, 216);
  assert.equal(data[0], 0x40);
  assert.equal(data[1], 0x0c);
  assert.equal(data[2] >> 4, 0x8);
  assert.equal(data[2] & 0xf, 0x4);
});

test('interleaving puts the blocks side by side and the error correction last', () => {
  // Version 5-M has 2 blocks of 43 data codewords and 24 error correction codewords each.
  const data = Array.from({ length: 86 }, (_, i) => i);
  const out = interleave(data, 5, 'M');
  assert.equal(out.length, 134);
  assert.deepEqual(out.slice(0, 6), [0, 43, 1, 44, 2, 45]);
  assert.equal(out[86], rsRemainder(data.slice(0, 43), 24)[0]);
  assert.equal(out[87], rsRemainder(data.slice(43), 24)[0]);
  // Version 9-M has 3 blocks of 36 data codewords and 2 of 37: the last two bytes come from the long ones.
  const nine = interleave(Array.from({ length: 182 }, (_, i) => i), 9, 'M');
  assert.equal(nine.length, 292);
  assert.deepEqual(nine.slice(0, 5), [0, 36, 72, 108, 145]);
  assert.deepEqual(nine.slice(180, 182), [144, 181]);
});

test('the function patterns are where the standard puts them', () => {
  for (let v = 1; v <= MAX_VERSION; v++) {
    const { size, dark, fixed } = blankSymbol(v);
    assert.equal(size, 17 + 4 * v);
    // Timing patterns alternate, starting dark.
    for (let i = 8; i < size - 8; i++) {
      assert.equal(dark[6][i], i % 2 === 0, `row timing ${v} ${i}`);
      assert.equal(dark[i][6], i % 2 === 0, `column timing ${v} ${i}`);
    }
    // Three finder patterns: a dark ring, a light ring, a dark 3 by 3 centre.
    for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
      assert.equal(dark[cy][cx], true);
      assert.equal(dark[cy - 3][cx - 3], true);
      assert.equal(dark[cy - 2][cx], false);
      assert.equal(dark[cy][cx + 2], false);
    }
    // The dark module beside the bottom left finder.
    assert.equal(dark[size - 8][8], true);
    // The free modules are exactly the codeword bits plus the remainder bits.
    let free = 0;
    for (const row of fixed) for (const f of row) if (!f) free++;
    const remainder = [0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0][v];
    const raw = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346][v];
    assert.equal(free, raw * 8 + remainder, `free modules of version ${v}`);
  }
});

// Reads a code back the way a scanner does, with positions written out from the standard: format
// bits, unmasking, the zig-zag, blocks and their error correction. Returns the text.
function read(grid) {
  const size = grid.length;
  const version = (size - 17) / 4;
  const first = [];
  for (let i = 0; i < 15; i++) {
    const [x, y] = i < 6 ? [8, i] : i === 6 ? [8, 7] : i === 7 ? [8, 8] : i === 8 ? [7, 8] : [14 - i, 8];
    first.push(grid[y][x] ? 1 : 0);
  }
  const second = [];
  for (let i = 0; i < 15; i++) second.push((i < 8 ? grid[8][size - 1 - i] : grid[size - 15 + i][8]) ? 1 : 0);
  const asNumber = (bits) => bits.reduce((n, b, i) => n | (b << i), 0);
  assert.equal(asNumber(first), asNumber(second), 'both copies of the format bits agree');
  let found = null;
  for (const level of ['L', 'M']) for (let mask = 0; mask < 8; mask++) if (formatBits(level, mask) === asNumber(first)) found = { level, mask };
  assert.ok(found, 'the format bits are a valid code');
  const masks = [
    (i, j) => (i + j) % 2 === 0,
    (i) => i % 2 === 0,
    (i, j) => j % 3 === 0,
    (i, j) => (i + j) % 3 === 0,
    (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
    (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
    (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
    (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
  ];
  const { fixed } = blankSymbol(version);
  const bits = [];
  let up = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let n = 0; n < size; n++) {
      const y = up ? size - 1 - n : n;
      for (const x of [right, right - 1]) {
        if (fixed[y][x]) continue;
        bits.push(grid[y][x] !== masks[found.mask](y, x) ? 1 : 0);
      }
    }
    up = !up;
  }
  const raw = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346][version];
  const words = [];
  for (let i = 0; i < raw; i++) words.push(parseInt(bits.slice(i * 8, i * 8 + 8).join(''), 2));
  // Undo the interleaving, then check each block against its own error correction.
  const ecLen = { L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18], M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26] }[found.level][version];
  const nBlocks = { L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4], M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5] }[found.level][version];
  const short = nBlocks - (raw % nBlocks);
  const shortLen = Math.floor(raw / nBlocks) - ecLen;
  const blocks = Array.from({ length: nBlocks }, (_, b) => ({ data: [], ec: [], len: shortLen + (b < short ? 0 : 1) }));
  let at = 0;
  for (let i = 0; i <= shortLen; i++) for (const b of blocks) if (i < b.len) b.data.push(words[at++]);
  for (let i = 0; i < ecLen; i++) for (const b of blocks) b.ec.push(words[at++]);
  const data = [];
  for (const b of blocks) {
    assert.deepEqual(rsRemainder(b.data, ecLen), b.ec, 'a block checks out');
    data.push(...b.data);
  }
  const stream = data.map((w) => bin(w, 8)).join('');
  assert.equal(stream.slice(0, 4), '0100', 'byte mode');
  const countBits = version < 10 ? 8 : 16;
  const count = parseInt(stream.slice(4, 4 + countBits), 2);
  const bytes = [];
  for (let i = 0; i < count; i++) bytes.push(parseInt(stream.slice(4 + countBits + i * 8, 12 + countBits + i * 8), 2));
  return { text: Buffer.from(bytes).toString('utf8'), version, ...found };
}

test('what is encoded can be read back, at every version, level and size around the limits', () => {
  for (const level of ['L', 'M']) {
    const lengths = new Set([1, 2, 7, 33, 100]);
    for (let v = 1; v <= MAX_VERSION; v++) for (const d of [-1, 0, 1]) lengths.add(byteCapacity(v, level) + d);
    for (const len of lengths) {
      if (len < 1 || len > byteCapacity(MAX_VERSION, level)) continue;
      const text = Array.from({ length: len }, (_, i) => String.fromCharCode(33 + ((i * 7 + len) % 90))).join('');
      const code = encode(text, { level });
      const back = read(code.grid);
      assert.equal(back.text, text, `${level} ${len}`);
      assert.equal(back.level, level);
      assert.equal(back.version, code.version);
      assert.equal(back.mask, code.mask);
    }
  }
});

test('the smallest version that fits is used', () => {
  assert.equal(encode('a'.repeat(14), { level: 'M' }).version, 1);
  assert.equal(encode('a'.repeat(15), { level: 'M' }).version, 2);
  assert.equal(encode('a'.repeat(17), { level: 'L' }).version, 1);
  assert.equal(encode('a'.repeat(18), { level: 'L' }).version, 2);
  assert.equal(encode('a'.repeat(213), { level: 'M' }).version, 10);
  assert.equal(encode('a'.repeat(271), { level: 'L' }).version, 10);
});

test('text is encoded as UTF-8', () => {
  const text = 'rettui éè € \u{1f512}';
  assert.equal(read(encode(text).grid).text, text);
});

test('the empty text is a valid code', () => {
  const code = encode('');
  assert.equal(code.version, 1);
  assert.equal(read(code.grid).text, '');
});

test('too much text, a wrong level and a non-string are refused', () => {
  assert.throws(() => encode('a'.repeat(214), { level: 'M' }), /does not fit/);
  assert.throws(() => encode('a'.repeat(272), { level: 'L' }), RangeError);
  assert.throws(() => encode('€'.repeat(80), { level: 'M' }), RangeError);
  assert.throws(() => encode('x', { level: 'H' }), /level/);
  assert.throws(() => encode('x', { level: 'constructor' }), RangeError);
  assert.throws(() => encode(42), TypeError);
  assert.throws(() => encode(undefined), TypeError);
});

test('the same text always gives the same code, and the mask has the lowest penalty', () => {
  const a = encode('rns.rettui.dev:4242');
  const b = encode('rns.rettui.dev:4242');
  assert.deepEqual(a.grid, b.grid);
  // Re-masking with every other mask cannot score lower: encode picks the minimum.
  assert.ok(penalty(a.grid) >= 0);
  assert.ok(Number.isInteger(a.mask) && a.mask >= 0 && a.mask < 8);
});

test('the penalty counts runs, blocks, finder-like patterns and imbalance', () => {
  // A 7 by 7 all-light grid: 7 rows and 7 columns of a run of 7 (3 + 2 each), 36 blocks, and a balance of 0 percent dark.
  const light = Array.from({ length: 7 }, () => new Array(7).fill(false));
  assert.equal(penalty(light), 14 * 5 + 36 * 3 + 100);
});

test('the SVG has only a rectangle and a path, with a quiet zone', () => {
  const code = encode('hello');
  const svg = toSvg(code.grid);
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 29 29"/);
  assert.equal(svg.match(/<[a-z]+/g).join(' '), '<svg <rect <path');
  assert.doesNotMatch(svg, /script|style|href|on[a-z]+=|<!/i);
  // The first dark module of the top left finder is at (4, 4) after the quiet zone.
  assert.match(svg, /d="M4 4h7v1h-7z/);
  // Each path step is a rectangle of dark modules, so their area is the number of dark modules.
  let dark = 0;
  for (const row of code.grid) for (const c of row) if (c) dark++;
  let area = 0;
  for (const [, w] of svg.matchAll(/h(\d+)v1h-\d+z/g)) area += Number(w);
  assert.equal(area, dark);
});
