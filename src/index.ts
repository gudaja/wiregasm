import {
  BeforeInitCallback,
  CheckFilterResponse,
  CompleteField,
  DissectSession,
  DownloadResponse,
  Follow,
  Frame,
  FramesResponse,
  LoadResponse,
  MapInput,
  Pref,
  PrefModule,
  PrefSetResult,
  TailResponse,
  TapConvResponse,
  TapExportObjectResponse,
  TapResponse,
  Vector,
  WiregasmLib,
  WiregasmLibOverrides,
  WiregasmLoader,
} from "./types";
import { preferenceSetCodeToError, vectorToArray } from "./utils";

const ALLOWED_TAP_KEYS = new Set([
  ...Array.from({ length: 15 }, (_, i) => `tap${i}`),
  ...Array.from({ length: 15 }, (_, i) => `filter${i}`),
]);

const ALLOWED_GRAPH_KEYS = new Set([
  "filter",
  "interval",
  ...Array.from({ length: 9 }, (_, i) => `graph${i}`),
  ...Array.from({ length: 9 }, (_, i) => `filter${i}`),
]);

const PCAPNG_BLOCK_TYPE_SHB = 0x0a0d0d0a;
const PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const PCAPNG_MIN_BLOCK_SIZE = 12;

/**
 * Endianness of the first section of a pcapng buffer.
 *
 * @param data Buffer that starts a capture file
 * @param defaultLittleEndian Used when the buffer does not start with a SHB
 */
function sectionEndianness(data: ArrayBufferView, defaultLittleEndian = true) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  if (
    view.byteLength < PCAPNG_MIN_BLOCK_SIZE ||
    view.getUint32(0, true) !== PCAPNG_BLOCK_TYPE_SHB
  ) {
    return defaultLittleEndian;
  }

  return view.getUint32(8, true) === PCAPNG_BYTE_ORDER_MAGIC;
}

/**
 * Verify that a buffer holds nothing but whole pcapng blocks.
 *
 * Only whole blocks may be appended to a live session, a partial block
 * terminates the tail in the library (WTAP_ERR_SHORT_READ).
 *
 * Appended chunks usually hold nothing but Enhanced Packet Blocks, so the
 * endianness of the section they belong to has to be supplied by the caller;
 * a Section Header Block in the buffer overrides it from that point on.
 *
 * @param data Buffer that is about to be appended
 * @param defaultLittleEndian Endianness of the section the buffer continues
 * @returns Endianness in effect at the end of the buffer
 * @throws Error if the buffer does not end on a block boundary
 */
export function validatePcapngBlocks(
  data: ArrayBufferView,
  defaultLittleEndian = true
): boolean {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  let littleEndian = defaultLittleEndian;
  let offset = 0;

  while (offset < view.byteLength) {
    const left = view.byteLength - offset;

    if (left < PCAPNG_MIN_BLOCK_SIZE) {
      throw new Error(
        `incomplete pcapng block at offset ${offset}: ${left} bytes left`
      );
    }

    // the block type of a SHB reads the same in both endiannesses, its
    // byte-order magic tells how the rest of the section is encoded
    if (view.getUint32(offset, true) === PCAPNG_BLOCK_TYPE_SHB) {
      littleEndian =
        view.getUint32(offset + 8, true) === PCAPNG_BYTE_ORDER_MAGIC;
    }

    const length = view.getUint32(offset + 4, littleEndian);

    if (length < PCAPNG_MIN_BLOCK_SIZE || length % 4 !== 0) {
      throw new Error(
        `invalid pcapng block length (${length}) at offset ${offset}`
      );
    }

    if (length > left) {
      throw new Error(
        `incomplete pcapng block at offset ${offset}: ${length} bytes expected, ${left} left`
      );
    }

    offset += length;
  }

  return littleEndian;
}

/**
 * Wraps the WiregasmLib lib functionality and manages a single DissectSession
 */
export class Wiregasm {
  lib: WiregasmLib;
  initialized: boolean;
  session: DissectSession | null;
  sessionPath: string | null;
  uploadDir: string;
  pluginsDir: string;

  // the session accepts appends, i.e. it was loaded in live mode and the
  // tail was neither finished nor broken by an error
  private tailOpen: boolean;

  // endianness of the pcapng section the file of the session ends with
  private tailLittleEndian: boolean;

  constructor() {
    this.initialized = false;
    this.session = null;
    this.sessionPath = null;
    this.tailOpen = false;
    this.tailLittleEndian = true;
  }

  /**
   * Initialize the wrapper and the Wiregasm module
   *
   * @param loader Loader function for the Emscripten module
   * @param overrides Overrides
   */
  async init(
    loader: WiregasmLoader,
    overrides: WiregasmLibOverrides = {},
    beforeInit: BeforeInitCallback = null
  ) {
    if (this.initialized) {
      return;
    }

    this.lib = await loader(overrides);

    if (beforeInit !== null) {
      await beforeInit(this.lib);
    }

    if (!this.lib.init()) {
      throw new Error("Failed to initialize Wiregasm");
    }

    this.uploadDir = this.lib.getUploadDirectory();
    this.pluginsDir = this.lib.getPluginsDirectory();
    this.initialized = true;
  }

  list_modules(): Vector<PrefModule> {
    return this.lib.listModules();
  }

  list_prefs(module: string): Vector<Pref> {
    return this.lib.listPreferences(module);
  }

  apply_prefs() {
    this.lib.applyPreferences();
  }

  set_pref(module: string, key: string, value: string) {
    const ret = this.lib.setPref(module, key, value);

    if (ret.code != PrefSetResult.PREFS_SET_OK) {
      const message =
        ret.error != "" ? ret.error : preferenceSetCodeToError(ret.code);
      throw new Error(
        `Failed to set preference (${module}.${key}): ${message}`
      );
    }
  }

  get_pref(module: string, key: string): Pref {
    const response = this.lib.getPref(module, key);
    if (response.code != 0) {
      throw new Error(`Failed to get preference (${module}.${key})`);
    }
    return response.data;
  }

  /**
   * Check the validity of a filter expression.
   *
   * @param filter A display filter expression
   */
  test_filter(filter: string): CheckFilterResponse {
    return this.lib.checkFilter(filter);
  }

  complete_filter(filter: string): { fields: CompleteField[] } {
    const out = this.lib.completeFilter(filter);
    return {
      fields: vectorToArray(out.fields),
    };
  }

  tap(taps: MapInput) {
    // Validate keys.
    if (!("tap0" in taps)) {
      throw new Error("tap0 is mandatory.");
    }
    if (!Object.keys(taps).every((k) => ALLOWED_TAP_KEYS.has(k))) {
      throw new Error(
        `Invalid arguments. Allowed keys are: ${Array.from(
          ALLOWED_GRAPH_KEYS
        ).join(", ")}.`
      );
    }

    const args = new this.lib.MapInput();
    Object.entries(taps).forEach(([k, v]) => args.set(k, v));

    const response = this.session.tap(args);
    return {
      error: response.error,
      taps: vectorToArray(response.taps).map((tap) => {
        let res;
        if (this.is_conv_tap(tap)) {
          res = {
            proto: tap.proto,
            tap: tap.tap,
            type: tap.type,
            geoip: tap.geoip,
            convs: vectorToArray(tap.convs),
            hosts: vectorToArray(tap.hosts),
          };
        } else if (this.is_eo_tap(tap)) {
          res = {
            proto: tap.proto,
            tap: tap.tap,
            type: tap.type,
            objects: vectorToArray(tap.objects),
          };
        } else {
          (tap as { delete: () => void }).delete();
          throw new Error("Unknown tap result");
        }
        (tap as TapResponse & { delete: () => void }).delete();
        return res;
      }),
    };
  }

  download(token: string): DownloadResponse {
    return this.session.download(token);
  }

  iograph(input: MapInput) {
    // Validate keys.
    if (!("graph0" in input)) {
      throw new Error("graph0 is mandatory.");
    }
    if (!Object.keys(input).every((k) => ALLOWED_GRAPH_KEYS.has(k))) {
      throw new Error(
        `Invalid arguments. Allowed keys are: ${Array.from(
          ALLOWED_GRAPH_KEYS
        ).join(", ")}.`
      );
    }

    const args = new this.lib.MapInput();
    Object.entries(input).forEach(([k, v]) => args.set(k, v));

    const out = this.session.iograph(args);
    return {
      ...out,
      iograph: vectorToArray(out.iograph).map((t) => ({
        items: vectorToArray(t.items),
      })),
    };
  }

  reload_lua_plugins() {
    this.lib.reloadLuaPlugins();
  }

  add_plugin(name: string, data: string | ArrayBufferView, opts: object = {}) {
    const path = this.pluginsDir + "/" + name;
    this.lib.FS.writeFile(path, data, opts);
  }

  /**
   * Load a packet trace file for analysis.
   *
   * @returns Response containing the status and summary
   */
  load(
    name: string,
    data: string | ArrayBufferView,
    opts: object = {}
  ): LoadResponse {
    return this.load_session(name, data, opts, false);
  }

  /**
   * Load a packet trace file in live (tail) mode.
   *
   * The sequential handle of the file is kept open, so that whole pcapng
   * blocks appended with `append()` can be read by the session. Only
   * uncompressed files are supported.
   *
   * @returns Response containing the status and summary
   */
  load_live(
    name: string,
    data: string | ArrayBufferView,
    opts: object = {}
  ): LoadResponse {
    return this.load_session(name, data, opts, true);
  }

  private load_session(
    name: string,
    data: string | ArrayBufferView,
    opts: object,
    live: boolean
  ): LoadResponse {
    if (this.session != null) {
      this.session.delete();
      this.session = null;
    }

    const path = this.uploadDir + "/" + name;
    this.lib.FS.writeFile(path, data, opts);

    this.sessionPath = path;
    this.tailOpen = false;
    this.tailLittleEndian =
      typeof data === "string" ? true : sectionEndianness(data);

    this.session = live
      ? new this.lib.DissectSession(path, true)
      : new this.lib.DissectSession(path);

    const ret = this.session.load();

    if (live && ret.code === 0) {
      this.tailOpen = true;
    }

    return ret;
  }

  /**
   * Append data to the capture file of a live session and dissect the
   * records that were appended.
   *
   * Only whole pcapng blocks may be appended, the buffer is validated
   * before it is written.
   *
   * @param data Buffer holding whole pcapng blocks
   * @returns Response containing the status and the new frame counts
   */
  append(data: ArrayBufferView): TailResponse {
    if (this.session === null || this.sessionPath === null) {
      throw new Error("No session loaded");
    }

    if (!this.tailOpen) {
      throw new Error("session is not tailable");
    }

    const littleEndian = validatePcapngBlocks(data, this.tailLittleEndian);

    this.lib.FS.writeFile(this.sessionPath, data, { flags: "a" });
    this.tailLittleEndian = littleEndian;

    const ret = this.session.continueTail();

    if (ret.code !== 0) {
      // the session does not accept further appends
      this.tailOpen = false;
    }

    return ret;
  }

  /**
   * Close the sequential handle of a live session. The frames that were
   * already read stay readable, further `append()` calls fail.
   */
  finish_tail(): boolean {
    if (this.session === null) {
      throw new Error("No session loaded");
    }

    this.tailOpen = false;

    return this.session.finishTail();
  }

  /**
   * Get Packet List information for a range of packets.
   *
   * @param filter Output those frames that pass this filter expression
   * @param skip Skip N frames
   * @param limit Limit the output to N frames
   */
  frames(filter: string, skip = 0, limit = 0): FramesResponse {
    return this.session.getFrames(filter, skip, limit);
  }

  /**
   * Get full information about a frame including the protocol tree.
   *
   * @param number Frame number
   */
  frame(num: number): Frame {
    return this.session.getFrame(num);
  }

  follow(follow: string, filter: string): Follow {
    return this.session.follow(follow, filter);
  }

  destroy() {
    if (this.initialized) {
      if (this.session !== null) {
        this.session.delete();
        this.session = null;
        this.sessionPath = null;
        this.tailOpen = false;
      }

      this.lib.destroy();
      this.initialized = false;
    }
  }

  /**
   * Returns the column headers
   */
  columns(): string[] {
    const vec = this.lib.getColumns();

    // convert it from a vector to array
    return vectorToArray(vec);
  }

  is_eo_tap(tap: any): tap is TapExportObjectResponse {
    return tap instanceof this.lib.TapExportObject;
  }

  is_conv_tap(tap: any): tap is TapConvResponse {
    return tap instanceof this.lib.TapConvResponse;
  }
}

export * from "./types";
export * from "./utils";
