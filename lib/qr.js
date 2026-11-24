// A small QR code encoder: byte mode, error correction level L or M, versions 1 to 10,
// all 8 masks, and an SVG writer. No dependency. The tables and rules are those of
// ISO/IEC 18004; test/qr.test.js checks the parts that have published answers.

// Codewords in the whole symbol (data and error correction), by version (index 0 is unused).
const RAW_CODEWORDS = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];
// Error correction codewords in each block, and the number of blocks, by level and version.
const EC_PER_BLOCK = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
};
const BLOCKS = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
};
// The two bits of the format information that name the level.
const LEVEL_BITS = { L: 1, M: 0 };
// Centres of the alignment patterns, by version.
const ALIGNMENT = [[], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

export const MAX_VERSION = 10;

// Arithmetic in GF(256) with the polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}

export function gfMultiply(a, b) {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
}

// The coefficients of (x - a^0)(x - a^1)...(x - a^(degree-1)), highest power first, without
// the leading 1.
export function rsGenerator(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMultiply(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly.slice(1);
}

// The error correction codewords of data: the remainder of data * x^degree divided by the generator.
export function rsRemainder(data, degree) {
  const gen = rsGenerator(degree);
  const rem = new Array(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ rem.shift();
    rem.push(0);
    for (let i = 0; i < degree; i++) rem[i] ^= gfMultiply(gen[i], factor);
  }
  return rem;
}

// The 15 format bits: 5 bits (level, mask) and 10 bits of BCH code, XOR 101010000010010.
export function formatBits(level, mask) {
  const data = (LEVEL_BITS[level] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

// The 18 version bits (version 7 and up): 6 bits and 12 bits of BCH code.
export function versionBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
}

// How many bytes fit in a version at a level.
export function byteCapacity(version, level) {
  const data = RAW_CODEWORDS[version] - EC_PER_BLOCK[level][version] * BLOCKS[level][version];
  const countBits = version < 10 ? 8 : 16;
  return Math.floor((data * 8 - 4 - countBits) / 8);
}

// The data codewords of a byte mode message: mode, length, bytes, terminator and padding.
export function dataCodewords(bytes, version, level) {
  const total = RAW_CODEWORDS[version] - EC_PER_BLOCK[level][version] * BLOCKS[level][version];
  const bits = [];
  const put = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4);
  put(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, total * 8 - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let pad = 0xec; out.length < total; pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}

// Splits the data into blocks, adds each block's error correction and interleaves them.
export function interleave(data, version, level) {
  const nBlocks = BLOCKS[level][version];
  const ecLen = EC_PER_BLOCK[level][version];
  const raw = RAW_CODEWORDS[version];
  const shortBlocks = nBlocks - (raw % nBlocks);
  const shortLen = Math.floor(raw / nBlocks) - ecLen;
  const blocks = [];
  let at = 0;
  for (let i = 0; i < nBlocks; i++) {
    const len = shortLen + (i < shortBlocks ? 0 : 1);
    const chunk = data.slice(at, at + len);
    at += len;
    blocks.push({ data: chunk, ec: rsRemainder(chunk, ecLen) });
  }
  const out = [];
  for (let i = 0; i <= shortLen; i++) {
    for (const b of blocks) if (i < b.data.length) out.push(b.data[i]);
  }
  for (let i = 0; i < ecLen; i++) for (const b of blocks) out.push(b.ec[i]);
  return out;
}

// The empty symbol: the function patterns drawn, and a map of the modules that are not data.
export function blankSymbol(version) {
  const size = 17 + 4 * version;
  const dark = Array.from({ length: size }, () => new Array(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, value) => {
    dark[y][x] = value;
    fixed[y][x] = true;
  };
  // Timing lines.
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  // Finder patterns with their separators.
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  // Alignment patterns, except where they would sit on a finder pattern.
  const centres = ALIGNMENT[version];
  for (const cy of centres) {
    for (const cx of centres) {
      const onFinder = (cx === 6 && cy === 6) || (cx === 6 && cy === centres[centres.length - 1]) || (cy === 6 && cx === centres[centres.length - 1]);
      if (onFinder) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  // Room for the format bits (drawn per mask), and the version bits.
  for (let i = 0; i < 9; i++) {
    fixed[8][i] = true;
    fixed[i][8] = true;
  }
  for (let i = 0; i < 8; i++) {
    fixed[8][size - 1 - i] = true;
    fixed[size - 1 - i][8] = true;
  }
  set(8, size - 8, true);
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(a, b, bit);
      set(b, a, bit);
    }
  }
  return { size, dark, fixed };
}

// Puts the codewords in the free modules, in the zig-zag order of the standard.
function placeData(symbol, codewords) {
  const { size, dark, fixed } = symbol;
  let bit = 0;
  const total = codewords.length * 8;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    // The vertical timing line is not part of any column pair.
    if (right === 6) right = 5;
    for (let n = 0; n < size; n++) {
      const y = upward ? size - 1 - n : n;
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        if (fixed[y][x]) continue;
        if (bit < total) dark[y][x] = ((codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1) === 1;
        bit++;
      }
    }
    upward = !upward;
  }
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function withMask(symbol, mask) {
  const { size, dark, fixed } = symbol;
  const out = dark.map((row) => row.slice());
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y][x] && MASKS[mask](x, y)) out[y][x] = !out[y][x];
  return out;
}

function drawFormat(grid, level, mask) {
  const size = grid.length;
  const bits = formatBits(level, mask);
  const bit = (i) => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) grid[i][8] = bit(i);
  grid[7][8] = bit(6);
  grid[8][8] = bit(7);
  grid[8][7] = bit(8);
  for (let i = 9; i < 15; i++) grid[8][14 - i] = bit(i);
  for (let i = 0; i < 8; i++) grid[8][size - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) grid[size - 15 + i][8] = bit(i);
}

// The penalty of a finished grid by the four rules of the standard; the mask with the lowest is used.
export function penalty(grid) {
  const size = grid.length;
  let score = 0;
  // Rule 1: five or more modules of one colour in a row or column.
  // Rule 3: the pattern dark-light-dark-dark-dark-light-dark with four light modules on one side.
  const lines = [];
  for (let i = 0; i < size; i++) {
    lines.push(grid[i].map(Number));
    lines.push(grid.map((row) => Number(row[i])));
  }
  const finderA = '10111010000';
  const finderB = '00001011101';
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= size; i++) {
      if (i < size && line[i] === line[i - 1]) run++;
      else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    const text = line.join('');
    for (let at = text.indexOf(finderA); at !== -1; at = text.indexOf(finderA, at + 1)) score += 40;
    for (let at = text.indexOf(finderB); at !== -1; at = text.indexOf(finderB, at + 1)) score += 40;
  }
  // Rule 2: blocks of 2 by 2 modules of one colour.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = grid[y][x];
      if (c === grid[y][x + 1] && c === grid[y + 1][x] && c === grid[y + 1][x + 1]) score += 3;
    }
  }
  // Rule 4: how far the share of dark modules is from half, in steps of 5 percent.
  let darkCount = 0;
  for (const row of grid) for (const c of row) if (c) darkCount++;
  const percent = (darkCount * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return score;
}

// Encodes text (as UTF-8 bytes) into a grid of booleans, true for a dark module. level is
// 'L' or 'M' (default 'M'). Throws a RangeError when the text does not fit in version 10.
export function encode(text, { level = 'M' } = {}) {
  if (typeof text !== 'string') throw new TypeError('text must be a string');
  if (!Object.hasOwn(LEVEL_BITS, level)) throw new RangeError('level must be L or M');
  const bytes = Buffer.from(text, 'utf8');
  let version = 1;
  while (version <= MAX_VERSION && byteCapacity(version, level) < bytes.length) version++;
  if (version > MAX_VERSION) throw new RangeError(`text of ${bytes.length} bytes does not fit in a version ${MAX_VERSION} QR code at level ${level} (at most ${byteCapacity(MAX_VERSION, level)})`);
  const symbol = blankSymbol(version);
  placeData(symbol, interleave(dataCodewords(bytes, version, level), version, level));
  let best = null;
  for (let mask = 0; mask < 8; mask++) {
    const grid = withMask(symbol, mask);
    drawFormat(grid, level, mask);
    const score = penalty(grid);
    if (best === null || score < best.score) best = { grid, score, mask };
  }
  return { version, level, mask: best.mask, size: symbol.size, grid: best.grid };
}

// An SVG of the code, black on white with the four module quiet zone readers need, whatever the
// page theme. It has no script, style or link: only a rectangle and one path.
export function toSvg(grid, { quiet = 4 } = {}) {
  const size = grid.length;
  const full = size + 2 * quiet;
  let d = '';
  for (let y = 0; y < size; y++) {
    let x = 0;
    while (x < size) {
      if (!grid[y][x]) {
        x++;
        continue;
      }
      let end = x;
      while (end < size && grid[y][end]) end++;
      d += `M${x + quiet} ${y + quiet}h${end - x}v1h-${end - x}z`;
      x = end;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${full} ${full}" width="${full * 6}" height="${full * 6}" shape-rendering="crispEdges"><rect width="${full}" height="${full}" fill="#fff"/><path d="${d}" fill="#000"/></svg>\n`;
}
