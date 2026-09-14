import * as fs from "fs/promises";

import { Wiregasm, WiregasmLibOverrides } from ".";

import loadWiregasm from "../built/bin/wiregasm.js";

// loading the wasm module + tailing is slower than the default 5s budget
jest.setTimeout(120000);

const SAMPLE = "samples/http2-16-ssl.pcapng";

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_EPB = 0x00000006;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

// overrides need to be copied over to every instance
const buildTestOverrides = (): WiregasmLibOverrides => {
  return {
    locateFile: (path, prefix) => {
      if (path.endsWith(".data")) return "built/bin/" + path;
      return prefix + path;
    },
    // supress all unwanted logs in test-suite
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    printErr: () => {},
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    print: () => {},
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    handleStatus: () => {},
  };
};

interface PcapngBlock {
  type: number;
  start: number;
  length: number;
}

/**
 * Minimal pcapng block splitter.
 *
 * Every block starts with block_type (4 bytes) and block_total_length
 * (4 bytes). The endianness of the section is taken from the byte-order
 * magic of the Section Header Block (offset 8).
 */
function splitPcapng(buf: Uint8Array): PcapngBlock[] {
  if (buf.byteLength < 12) {
    throw new Error("not a pcapng file: too short");
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  if (view.getUint32(0, true) !== BLOCK_SHB) {
    throw new Error("not a pcapng file: first block is not an SHB");
  }

  let little: boolean;
  if (view.getUint32(8, true) === BYTE_ORDER_MAGIC) {
    little = true;
  } else if (view.getUint32(8, false) === BYTE_ORDER_MAGIC) {
    little = false;
  } else {
    throw new Error("not a pcapng file: bad byte-order magic");
  }

  const blocks: PcapngBlock[] = [];
  let offset = 0;

  while (offset + 12 <= buf.byteLength) {
    const type = view.getUint32(offset, little);
    const length = view.getUint32(offset + 4, little);

    if (length < 12 || length % 4 !== 0) {
      throw new Error(
        "invalid block_total_length " + length + " at offset " + offset
      );
    }
    if (offset + length > buf.byteLength) {
      throw new Error("truncated block at offset " + offset);
    }

    blocks.push({ type: type, start: offset, length: length });
    offset += length;
  }

  if (offset !== buf.byteLength) {
    throw new Error("trailing garbage at offset " + offset);
  }

  return blocks;
}

/**
 * Bytes of blocks[from..to) as one buffer (always whole blocks).
 */
function sliceBlocks(
  buf: Uint8Array,
  blocks: PcapngBlock[],
  from: number,
  to: number
): Uint8Array {
  if (from >= to) {
    throw new Error("empty block range " + from + ".." + to);
  }
  const first = blocks[from];
  const last = blocks[to - 1];
  return buf.subarray(first.start, last.start + last.length);
}

/**
 * Index of the first block after the SHB + leading IDBs (= the header).
 */
function headerBlockCount(blocks: PcapngBlock[]): number {
  let i = 1; // blocks[0] is the SHB
  while (i < blocks.length && blocks[i].type === BLOCK_IDB) {
    i++;
  }
  return i;
}

/**
 * Index of the block just after the n-th EPB.
 */
function afterNthEpb(blocks: PcapngBlock[], n: number): number {
  let seen = 0;
  for (let i = 0; i < blocks.length; i++) {
    if (blocks[i].type === BLOCK_EPB) {
      seen++;
      if (seen === n) {
        return i + 1;
      }
    }
  }
  throw new Error("sample does not contain " + n + " EPB blocks");
}

// Embind handles must be released explicitly; cleanup must never fail a test
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function safeDelete(obj: any) {
  try {
    if (obj && typeof obj.delete === "function") {
      obj.delete();
    }
  } catch (e) {
    // ignore - value objects may not own a handle
  }
}

interface FramesSnapshot {
  matched: number;
  count: number;
  rows: string[][];
}

/**
 * Copies a FramesResponse into plain JS and releases every Embind handle.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function readFrames(res: any): FramesSnapshot {
  const rows: string[][] = [];
  const vec = res.frames;
  const count = vec.size();

  for (let i = 0; i < count; i++) {
    const meta = vec.get(i);
    const cols = meta.columns;
    const row: string[] = [];
    for (let j = 0; j < cols.size(); j++) {
      row.push(cols.get(j));
    }
    rows.push(row);
    safeDelete(cols);
    safeDelete(meta);
  }

  safeDelete(vec);

  return { matched: res.matched, count: count, rows: rows };
}

interface PlainReference {
  packet_count: number;
  file_length: number;
  all: FramesSnapshot;
  tcp_matched: number;
  last_row: string[];
  last_tree_size: number;
}

describe("Wiregasm Library Wrapper - live tail", () => {
  // the live API is added by the implementation agent; keep this file
  // compilable against the current (pre-change) type declarations
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wg: any = new Wiregasm();

  let data: Uint8Array;
  let blocks: PcapngBlock[];
  let headerWithThreeEpbs: Uint8Array;
  let restPart1: Uint8Array;
  let restPart2: Uint8Array;
  let plain: PlainReference;

  beforeAll(async () => {
    data = await fs.readFile(SAMPLE);
    blocks = splitPcapng(data);

    const headerBlocks = headerBlockCount(blocks);
    const afterThird = afterNthEpb(blocks, 3);
    // rest of the file, split into two chunks on block boundaries
    const middle = afterThird + Math.floor((blocks.length - afterThird) / 2);

    headerWithThreeEpbs = sliceBlocks(data, blocks, 0, afterThird);
    restPart1 = sliceBlocks(data, blocks, afterThird, middle);
    restPart2 = sliceBlocks(data, blocks, middle, blocks.length);

    expect(headerBlocks).toBeGreaterThanOrEqual(2);
    expect(afterThird).toBeGreaterThan(headerBlocks);

    // reference values from a plain, one-shot load of the whole file
    // (separate instance so the live session below is untouched)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ref: any = new Wiregasm();
    await ref.init(loadWiregasm, buildTestOverrides());

    const loaded = ref.load("plain.pcapng", data);
    expect(loaded.code).toEqual(0);

    const all = readFrames(ref.frames("", 0, 0));
    const tcp = readFrames(ref.frames("tcp", 0, 0));
    const lastFrame = ref.frame(loaded.summary.packet_count);
    const lastTreeSize = lastFrame.tree.size();

    safeDelete(lastFrame.tree);
    safeDelete(lastFrame.data_sources);
    safeDelete(lastFrame.comments);
    safeDelete(lastFrame.follow);

    plain = {
      packet_count: loaded.summary.packet_count,
      file_length: loaded.summary.file_length,
      all: all,
      tcp_matched: tcp.matched,
      last_row: all.rows[all.rows.length - 1],
      last_tree_size: lastTreeSize,
    };

    ref.destroy();

    await wg.init(loadWiregasm, buildTestOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("pcapng splitter sees the expected sample layout", () => {
    expect(blocks.length).toBeGreaterThan(4);
    expect(blocks[0].type).toEqual(BLOCK_SHB);
    expect(blocks[1].type).toEqual(BLOCK_IDB);
    expect(blocks.filter((b) => b.type === BLOCK_EPB).length).toBeGreaterThan(
      3
    );

    // chunks are contiguous, whole-block and cover the whole file
    expect(
      headerWithThreeEpbs.byteLength +
        restPart1.byteLength +
        restPart2.byteLength
    ).toEqual(data.byteLength);
    expect(restPart1.byteLength).toBeGreaterThan(0);
    expect(restPart2.byteLength).toBeGreaterThan(0);

    // the reference load worked
    expect(plain.packet_count).toBeGreaterThan(3);
    expect(plain.all.matched).toEqual(plain.packet_count);
    expect(plain.tcp_matched).toBeGreaterThan(0);
  });

  test("load_live accepts a header plus the first 3 EPB blocks", () => {
    const ret = wg.load_live("live.pcapng", headerWithThreeEpbs);

    expect(ret.code).toEqual(0);
    expect(ret.error).toEqual("");
    expect(ret.summary.packet_count).toEqual(3);

    const frames = readFrames(wg.frames("", 0, 0));
    expect(frames.matched).toEqual(3);
    expect(frames.count).toEqual(3);
  });

  test("first append dissects the newly written blocks", () => {
    const ret = wg.append(restPart1);

    expect(ret.code).toEqual(0);
    expect(ret.error).toEqual("");
    expect(ret.new_frames).toBeGreaterThan(0);
    expect(ret.packet_count).toEqual(3 + ret.new_frames);
    expect(ret.packet_count).toBeLessThan(plain.packet_count);
    expect(ret.file_length).toEqual(
      headerWithThreeEpbs.byteLength + restPart1.byteLength
    );
  });

  test("filter cache is warmed up before the last append", () => {
    const before = readFrames(wg.frames("tcp", 0, 0));

    expect(before.matched).toBeGreaterThan(0);
    expect(before.matched).toBeLessThanOrEqual(plain.tcp_matched);
    expect(before.count).toEqual(before.matched);
  });

  test("second append reaches the packet count of a plain load", () => {
    const ret = wg.append(restPart2);

    expect(ret.code).toEqual(0);
    expect(ret.error).toEqual("");
    expect(ret.new_frames).toBeGreaterThan(0);
    expect(ret.packet_count).toEqual(plain.packet_count);
    expect(ret.file_length).toEqual(data.byteLength);
  });

  test("filter cache is extended incrementally after the append", () => {
    const after = readFrames(wg.frames("tcp", 0, 0));

    expect(after.matched).toEqual(plain.tcp_matched);
    expect(after.count).toEqual(plain.tcp_matched);
  });

  test("empty filter matches every tailed frame", () => {
    const all = readFrames(wg.frames("", 0, 0));

    expect(all.matched).toEqual(plain.packet_count);
    expect(all.count).toEqual(plain.packet_count);
  });

  test("the last tailed frame has a protocol tree", () => {
    const frame = wg.frame(plain.packet_count);

    expect(frame.number).toEqual(plain.packet_count);
    expect(frame.tree.size()).toBeGreaterThan(0);
    expect(frame.tree.size()).toEqual(plain.last_tree_size);
    expect(frame.data_sources.size()).toBeGreaterThan(0);

    safeDelete(frame.tree);
    safeDelete(frame.data_sources);
    safeDelete(frame.comments);
    safeDelete(frame.follow);
  });

  test("relative timestamps survive tailing", () => {
    const all = readFrames(wg.frames("", 0, 0));
    const lastRow = all.rows[all.rows.length - 1];

    // columns: ["No.", "Time", "Source", "Destination", ...]
    expect(lastRow[1]).toEqual(plain.last_row[1]);
    expect(parseFloat(lastRow[1])).toBeGreaterThan(0);
  });

  test("appending a partial block throws", () => {
    const oneBlock = sliceBlocks(
      data,
      blocks,
      headerBlockCount(blocks),
      headerBlockCount(blocks) + 1
    );
    const cutMidBlock = oneBlock.subarray(0, oneBlock.byteLength - 4);

    expect(() => {
      wg.append(cutMidBlock);
    }).toThrow();

    // not even a block header is complete here
    expect(() => {
      wg.append(oneBlock.subarray(0, 6));
    }).toThrow();
  });
});

describe("Wiregasm Library - DissectSession tail edge cases", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wg: any = new Wiregasm();

  beforeAll(() => {
    return wg.init(loadWiregasm, buildTestOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("continueTail on a non-live session fails without crashing", async () => {
    const data = await fs.readFile(SAMPLE);
    const path = "/uploads/nonlive.pcapng";
    wg.lib.FS.writeFile(path, data);

    const sess = new wg.lib.DissectSession(path);
    const loaded = sess.load();
    expect(loaded.code).toEqual(0);

    const tail = sess.continueTail();
    expect(tail.code).not.toEqual(0);
    expect(typeof tail.error).toEqual("string");
    expect(tail.error.length).toBeGreaterThan(0);

    // the session is still usable
    const frames = readFrames(sess.getFrames("", 0, 0));
    expect(frames.matched).toEqual(loaded.summary.packet_count);

    sess.delete();
  });

  test("continueTail after finishTail fails, session still answers", async () => {
    const data = await fs.readFile(SAMPLE);
    const blocks = splitPcapng(data);
    const afterThird = afterNthEpb(blocks, 3);

    const head = sliceBlocks(data, blocks, 0, afterThird);
    const rest = sliceBlocks(data, blocks, afterThird, blocks.length);

    const path = "/uploads/live-raw.pcapng";
    wg.lib.FS.writeFile(path, head);

    const sess = new wg.lib.DissectSession(path, true);
    const loaded = sess.load();
    expect(loaded.code).toEqual(0);
    expect(loaded.summary.packet_count).toEqual(3);

    wg.lib.FS.writeFile(path, rest, { flags: "a" });

    const tail = sess.continueTail();
    expect(tail.code).toEqual(0);
    expect(tail.new_frames).toBeGreaterThan(0);
    expect(tail.packet_count).toBeGreaterThan(3);
    expect(tail.file_length).toEqual(data.byteLength);

    expect(sess.finishTail()).toBeTruthy();

    const afterFinish = sess.continueTail();
    expect(afterFinish.code).not.toEqual(0);

    const frames = readFrames(sess.getFrames("", 0, 0));
    expect(frames.matched).toEqual(tail.packet_count);
    expect(frames.count).toEqual(tail.packet_count);

    sess.delete();
  });
});
