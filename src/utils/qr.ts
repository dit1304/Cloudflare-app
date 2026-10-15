/**
 * Local QR code -> PNG generator.
 * Pure JS: qrcode-generator builds the modules, a minimal PNG encoder
 * renders them. No third-party service, so secrets never leave the Worker.
 */
import qrcode from 'qrcode-generator';

const CRC_TABLE: Uint32Array = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  dv.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)));
  return out;
}

/**
 * Render text as a QR code PNG (grayscale, 8-bit).
 * @param text  data to encode
 * @param scale pixels per module
 * @param border quiet-zone modules around the code
 */
export async function generateQrPng(
  text: string,
  scale = 8,
  border = 4
): Promise<Uint8Array> {
  const qr = qrcode(0, 'M'); // 0 = auto type number
  qr.addData(text);
  qr.make();

  const n = qr.getModuleCount();
  const size = (n + border * 2) * scale;
  const stride = size + 1; // +1 filter byte per scanline
  const raw = new Uint8Array(stride * size);

  for (let y = 0; y < size; y++) {
    raw[y * stride] = 0; // filter type: None
    for (let x = 0; x < size; x++) {
      const mx = Math.floor(x / scale) - border;
      const my = Math.floor(y / scale) - border;
      const dark =
        mx >= 0 && my >= 0 && mx < n && my < n ? qr.isDark(my, mx) : false;
      raw[y * stride + 1 + x] = dark ? 0 : 255;
    }
  }

  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  await writer.write(raw);
  await writer.close();
  const compressed = new Uint8Array(
    await new Response(cs.readable).arrayBuffer()
  );

  const ihdr = new Uint8Array(13);
  const dv = new DataView(ihdr.buffer);
  dv.setUint32(0, size);
  dv.setUint32(4, size);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // color type: grayscale

  const sig = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
  const parts = [
    sig,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', compressed),
    pngChunk('IEND', new Uint8Array(0)),
  ];
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
