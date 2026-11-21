// Pure JavaScript ISO/IEC 18004 QR Code Generator (Byte mode, Versions 1-12, ECC M)
// Zero external dependencies — runs 100% offline in browsers and Android WebView.

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function buildRsGenerator(ecCount) {
  let poly = [1];
  for (let i = 0; i < ecCount; i++) {
    const next = new Array(poly.length + 1).fill(0);
    const factor = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], factor);
    }
    poly = next;
  }
  return poly;
}

function rsRemainder(data, ecCount) {
  const gen = buildRsGenerator(ecCount);
  const res = new Uint8Array(data.length + ecCount);
  res.set(data, 0);
  for (let i = 0; i < data.length; i++) {
    const coef = res[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        res[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return res.slice(data.length);
}

// Version table for ECC Level M:
// [version, totalDataBytes, ecBytesPerBlock, group1Blocks, group1DataBytes, group2Blocks, group2DataBytes, alignmentPositions]
const VERSION_TABLE_M = [
  null,
  [1, 16, 10, 1, 16, 0, 0, []],
  [2, 28, 16, 1, 28, 0, 0, [6, 18]],
  [3, 44, 26, 1, 44, 0, 0, [6, 22]],
  [4, 64, 18, 2, 32, 0, 0, [6, 26]],
  [5, 86, 24, 2, 43, 0, 0, [6, 30]],
  [6, 108, 16, 4, 27, 0, 0, [6, 34]],
  [7, 124, 18, 4, 31, 0, 0, [6, 22, 38]],
  [8, 154, 22, 2, 38, 2, 39, [6, 24, 42]],
  [9, 182, 22, 3, 36, 2, 37, [6, 26, 46]],
  [10, 216, 26, 4, 43, 1, 44, [6, 28, 50]],
  [11, 254, 30, 1, 50, 4, 51, [6, 30, 54]],
  [12, 290, 22, 6, 36, 2, 37, [6, 32, 58]],
];

// 15-bit format info for ECC M (00) + mask 0..7, precomputed with BCH(15,5) + mask 0x5412
const FORMAT_INFO_M = [
  0x5412, // mask 0
  0x5125, // mask 1
  0x5e7c, // mask 2
  0x5b4b, // mask 3
  0x45f9, // mask 4
  0x40ce, // mask 5
  0x4f97, // mask 6
  0x4aa0, // mask 7
];

// 18-bit version info for versions 7..12
const VERSION_INFO = {
  7: 0x07c94,
  8: 0x085bc,
  9: 0x09a99,
  10: 0x0a4d3,
  11: 0x0bbf6,
  12: 0x0c762,
};

function selectVersionM(byteLen) {
  for (let v = 1; v < VERSION_TABLE_M.length; v++) {
    const row = VERSION_TABLE_M[v];
    const countBits = v <= 9 ? 8 : 16;
    const capacityBits = row[1] * 8;
    const neededBits = 4 + countBits + byteLen * 8;
    if (neededBits <= capacityBits) {
      return row;
    }
  }
  throw new Error('Texto excede o limite suportado para QR Code offline.');
}

function encodeCodewords(bytes, spec) {
  const [version, totalDataBytes, ecBytesPerBlock, g1Blocks, g1Data, g2Blocks, g2Data] = spec;
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) {
      bits.push((val >>> i) & 1);
    }
  };

  // Byte mode indicator (0100) + character count
  pushBits(0b0100, 4);
  pushBits(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) {
    pushBits(b, 8);
  }

  const maxBits = totalDataBytes * 8;
  const terminatorLen = Math.min(4, maxBits - bits.length);
  pushBits(0, terminatorLen);

  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  const dataBytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    let val = 0;
    for (let j = 0; j < 8; j++) {
      val = (val << 1) | bits[i + j];
    }
    dataBytes.push(val);
  }

  let padToggle = 0;
  while (dataBytes.length < totalDataBytes) {
    dataBytes.push(padToggle === 0 ? 0xec : 0x11);
    padToggle ^= 1;
  }

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;

  for (let i = 0; i < g1Blocks; i++) {
    const block = Uint8Array.from(dataBytes.slice(offset, offset + g1Data));
    offset += g1Data;
    dataBlocks.push(block);
    ecBlocks.push(rsRemainder(block, ecBytesPerBlock));
  }
  for (let i = 0; i < g2Blocks; i++) {
    const block = Uint8Array.from(dataBytes.slice(offset, offset + g2Data));
    offset += g2Data;
    dataBlocks.push(block);
    ecBlocks.push(rsRemainder(block, ecBytesPerBlock));
  }

  const interleaved = [];
  const maxDataLen = Math.max(g1Data, g2Data);
  for (let i = 0; i < maxDataLen; i++) {
    for (const block of dataBlocks) {
      if (i < block.length) interleaved.push(block[i]);
    }
  }
  for (let i = 0; i < ecBytesPerBlock; i++) {
    for (const ec of ecBlocks) {
      interleaved.push(ec[i]);
    }
  }

  return interleaved;
}

function createMatrix(version, alignmentPositions) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Uint8Array(size));
  const reserved = Array.from({ length: size }, () => new Uint8Array(size));

  const setFixed = (r, c, dark) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    modules[r][c] = dark ? 1 : 0;
    reserved[r][c] = 1;
  };

  const placeFinder = (top, left) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = top + r;
        const cc = left + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6;
        const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const isCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setFixed(rr, cc, inOuter && (isBorder || isCore));
      }
    }
  };

  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    setFixed(6, i, i % 2 === 0);
    setFixed(i, 6, i % 2 === 0);
  }

  // Dark module
  setFixed(4 * version + 9, 8, true);

  // Alignment patterns
  if (alignmentPositions.length > 0) {
    for (const r of alignmentPositions) {
      for (const c of alignmentPositions) {
        if (reserved[r][c]) continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const dark = Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0);
            setFixed(r + dr, c + dc, dark);
          }
        }
      }
    }
  }

  // Reserve format info areas
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      reserved[8][i] = 1;
      reserved[i][8] = 1;
    }
  }
  for (let i = size - 8; i < size; i++) {
    reserved[8][i] = 1;
    reserved[i][8] = 1;
  }

  // Version info (versions >= 7)
  if (version >= 7 && VERSION_INFO[version]) {
    const vBits = VERSION_INFO[version];
    for (let i = 0; i < 18; i++) {
      const dark = ((vBits >>> i) & 1) === 1;
      const r = Math.floor(i / 3);
      const c = size - 11 + (i % 3);
      setFixed(r, c, dark);
      setFixed(c, r, dark);
    }
  }

  return { size, modules, reserved };
}

function applyFormatInfo(modules, size, maskId) {
  const fmt = FORMAT_INFO_M[maskId];
  for (let i = 0; i < 15; i++) {
    const dark = ((fmt >>> i) & 1) === 1 ? 1 : 0;
    if (i < 6) modules[i][8] = dark;
    else if (i < 8) modules[i + 1][8] = dark;
    else modules[size - 15 + i][8] = dark;

    if (i < 8) modules[8][size - i - 1] = dark;
    else if (i < 9) modules[8][15 - i] = dark;
    else modules[8][15 - i - 1] = dark;
  }
}

function maskBit(maskId, r, c) {
  switch (maskId) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return false;
  }
}

function evaluatePenalty(modules, size) {
  let penalty = 0;

  // Rule 1: adjacent runs >= 5
  for (let r = 0; r < size; r++) {
    let runColor = modules[r][0];
    let runLen = 1;
    for (let c = 1; c < size; c++) {
      if (modules[r][c] === runColor) {
        runLen++;
      } else {
        if (runLen >= 5) penalty += 3 + (runLen - 5);
        runColor = modules[r][c];
        runLen = 1;
      }
    }
    if (runLen >= 5) penalty += 3 + (runLen - 5);
  }
  for (let c = 0; c < size; c++) {
    let runColor = modules[0][c];
    let runLen = 1;
    for (let r = 1; r < size; r++) {
      if (modules[r][c] === runColor) {
        runLen++;
      } else {
        if (runLen >= 5) penalty += 3 + (runLen - 5);
        runColor = modules[r][c];
        runLen = 1;
      }
    }
    if (runLen >= 5) penalty += 3 + (runLen - 5);
  }

  // Rule 2: 2x2 blocks
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const sum =
        modules[r][c] +
        modules[r][c + 1] +
        modules[r + 1][c] +
        modules[r + 1][c + 1];
      if (sum === 0 || sum === 4) penalty += 3;
    }
  }

  // Rule 3: finder-like patterns
  const isPatA = (arr, i) =>
    arr[i] === 1 &&
    arr[i + 1] === 0 &&
    arr[i + 2] === 1 &&
    arr[i + 3] === 1 &&
    arr[i + 4] === 1 &&
    arr[i + 5] === 0 &&
    arr[i + 6] === 1 &&
    arr[i + 7] === 0 &&
    arr[i + 8] === 0 &&
    arr[i + 9] === 0 &&
    arr[i + 10] === 0;
  const isPatB = (arr, i) =>
    arr[i] === 0 &&
    arr[i + 1] === 0 &&
    arr[i + 2] === 0 &&
    arr[i + 3] === 0 &&
    arr[i + 4] === 1 &&
    arr[i + 5] === 0 &&
    arr[i + 6] === 1 &&
    arr[i + 7] === 1 &&
    arr[i + 8] === 1 &&
    arr[i + 9] === 0 &&
    arr[i + 10] === 1;

  for (let r = 0; r < size; r++) {
    for (let c = 0; c <= size - 11; c++) {
      if (isPatA(modules[r], c) || isPatB(modules[r], c)) penalty += 40;
    }
  }
  const col = new Uint8Array(size);
  for (let c = 0; c < size; c++) {
    for (let r = 0; r < size; r++) col[r] = modules[r][c];
    for (let r = 0; r <= size - 11; r++) {
      if (isPatA(col, r) || isPatB(col, r)) penalty += 40;
    }
  }

  // Rule 4: dark ratio
  let dark = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) dark += modules[r][c];
  }
  const percent = (dark * 100) / (size * size);
  const k = Math.abs(Math.floor(percent / 5) * 5 - 50) / 5;
  penalty += k * 10;

  return penalty;
}

export function generateQrMatrix(text) {
  const bytes = new TextEncoder().encode(String(text));
  const spec = selectVersionM(bytes.length);
  const version = spec[0];
  const alignmentPositions = spec[7];
  const codewords = encodeCodewords(bytes, spec);

  const bitStream = [];
  for (const cw of codewords) {
    for (let i = 7; i >= 0; i--) {
      bitStream.push((cw >>> i) & 1);
    }
  }

  let bestMatrix = null;
  let bestPenalty = Infinity;

  for (let maskId = 0; maskId < 8; maskId++) {
    const { size, modules, reserved } = createMatrix(version, alignmentPositions);
    let bitIdx = 0;
    let upward = true;

    for (let right = size - 1; right > 0; right -= 2) {
      if (right === 6) right = 5;
      for (let step = 0; step < size; step++) {
        const r = upward ? size - 1 - step : step;
        for (let dx = 0; dx < 2; dx++) {
          const c = right - dx;
          if (reserved[r][c]) continue;
          const bit = bitIdx < bitStream.length ? bitStream[bitIdx++] : 0;
          modules[r][c] = (bit ^ (maskBit(maskId, r, c) ? 1 : 0)) & 1;
        }
      }
      upward = !upward;
    }

    applyFormatInfo(modules, size, maskId);
    const penalty = evaluatePenalty(modules, size);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMatrix = modules;
    }
  }

  return bestMatrix;
}

export function renderQrToCanvas(canvas, text, options = {}) {
  if (!canvas) return;
  const matrix = generateQrMatrix(text);
  const count = matrix.length;
  const quiet = options.quietZone ?? 4;
  const modulePx = options.moduleSize ?? 5;
  const totalPx = (count + quiet * 2) * modulePx;

  canvas.width = totalPx;
  canvas.height = totalPx;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, totalPx, totalPx);

  ctx.fillStyle = '#080c14';
  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (matrix[r][c]) {
        ctx.fillRect((c + quiet) * modulePx, (r + quiet) * modulePx, modulePx, modulePx);
      }
    }
  }
}
