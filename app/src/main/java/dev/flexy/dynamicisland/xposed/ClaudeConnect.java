package dev.flexy.dynamicisland.xposed;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.zip.GZIPInputStream;

// Follows the Claude app's chat subscription: Connect protocol messages (5-byte envelope + protobuf)
// carried in HTTP/2 DATA frames on the decrypted TLS stream. Only message shapes are inspected.
//
// Every event message is 1{ 10{..} 11:varint <event> } where the event field is:
//   14 / 5     the user's message was sent
//   2{6{..}}   status update while the reply is being prepared
//   2{2:..}    text delta
//   1{3{7=1}}  entity upsert where the reply message is marked complete
final class ClaudeConnect {
    private static final Map<Object, ClaudeConnect> CONNS = Collections.synchronizedMap(new WeakHashMap<>());
    private static final int MAX_BODY = 4 << 20;
    private static final int MAX_INFLATED = 8 << 20;

    private int state; // 0 = waiting for the server's first frame, 1 = HTTP/2, 2 = something else
    private final byte[] head = new byte[9];
    private int headFill;
    private boolean inFrame;
    private int remaining;
    private int type;
    private int flags;
    private int streamId;
    private boolean padPending;
    private int padLen;
    private final Map<Integer, Envelope> streams = new HashMap<>();

    private ClaudeConnect() {
    }

    static void feed(Object stream, byte[] buf, int off, int len) {
        ClaudeConnect c;
        synchronized (CONNS) {
            c = CONNS.get(stream);
            if (c == null) {
                c = new ClaudeConnect();
                CONNS.put(stream, c);
            }
        }
        synchronized (c) {
            c.consume(buf, off, len);
        }
    }

    private void consume(byte[] buf, int off, int len) {
        int i = off;
        int end = off + len;
        while (i < end) {
            if (state == 2) return;
            if (!inFrame) {
                int n = Math.min(9 - headFill, end - i);
                System.arraycopy(buf, i, head, headFill, n);
                headFill += n;
                i += n;
                if (headFill < 9) return;
                headFill = 0;
                remaining = ((head[0] & 0xff) << 16) | ((head[1] & 0xff) << 8) | (head[2] & 0xff);
                type = head[3] & 0xff;
                flags = head[4] & 0xff;
                streamId = ((head[5] & 0x7f) << 24) | ((head[6] & 0xff) << 16) | ((head[7] & 0xff) << 8) | (head[8] & 0xff);
                if (state == 0) {
                    // A server's HTTP/2 connection always opens with a SETTINGS frame on stream 0.
                    if (type != 4 || streamId != 0) {
                        state = 2;
                        return;
                    }
                    state = 1;
                }
                inFrame = true;
                padPending = type == 0 && (flags & 0x8) != 0;
                padLen = 0;
                if (type == 3 || (type == 1 && (flags & 0x1) != 0)) streams.remove(streamId);
                if (remaining == 0) endFrame();
                continue;
            }
            int n = Math.min(remaining, end - i);
            if (type == 0) dataBytes(buf, i, n);
            i += n;
            remaining -= n;
            if (remaining == 0) endFrame();
        }
    }

    private void endFrame() {
        inFrame = false;
        if (type == 0 && (flags & 0x1) != 0) streams.remove(streamId);
    }

    private void dataBytes(byte[] buf, int off, int n) {
        Envelope env = streams.get(streamId);
        if (env == null) {
            env = new Envelope();
            streams.put(streamId, env);
        }
        for (int j = 0; j < n; j++) {
            if (padPending) {
                padLen = buf[off + j] & 0xff;
                padPending = false;
                continue;
            }
            // Bytes left in this frame, counting the current one; the last padLen are padding.
            if (remaining - j <= padLen) continue;
            if (!env.accept(buf[off + j])) return;
        }
    }

    private static final class Envelope {
        int mode = -1; // -1 = unknown, 0 = not enveloped, 1 = enveloped
        final byte[] h = new byte[5];
        int hf;
        int flag;
        int len;
        int got;
        byte[] body;

        // Returns false once the stream turns out not to carry envelopes.
        boolean accept(byte b) {
            if (mode == -1) mode = (b & 0xff) <= 3 ? 1 : 0;
            if (mode == 0) return false;
            if (hf < 5) {
                h[hf++] = b;
                if (hf < 5) return true;
                flag = h[0] & 0xff;
                len = ((h[1] & 0xff) << 24) | ((h[2] & 0xff) << 16) | ((h[3] & 0xff) << 8) | (h[4] & 0xff);
                if (flag > 3 || len < 0) {
                    mode = 0;
                    return false;
                }
                got = 0;
                body = len <= MAX_BODY ? new byte[len] : null;
                if (len == 0) done();
                return true;
            }
            if (body != null) body[got] = b;
            got++;
            if (got == len) done();
            return true;
        }

        void done() {
            hf = 0;
            byte[] data = body;
            body = null;
            // Flag 2 is Connect's end-of-stream message (JSON); oversized bodies were not kept.
            if (data == null || (flag & 0x2) != 0) return;
            try {
                if ((flag & 0x1) != 0) data = gunzip(data);
                if (data != null) onMessage(data);
            } catch (Throwable t) {
                XLog.e("claude connect message", t);
            }
        }
    }

    private static void onMessage(byte[] d) {
        long top = find(d, 0, d.length, 1);
        if (top < 0) return;
        int mStart = (int) (top >>> 32);
        int mEnd = (int) top;
        // Every chat event carries fields 10 and 11 next to the event itself.
        if (find(d, mStart, mEnd, 10) < 0 && find(d, mStart, mEnd, 11) < 0) return;
        Event e = new Event();
        Proto.each(d, mStart, mEnd, (field, wire, value, from, to) -> {
            if (wire != 2) return;
            if (field == 14 || field == 5) {
                e.sent = true;
            } else if (field == 2) {
                if (find(d, from, to, 2) >= 0) e.text = true;
                else if (find(d, from, to, 6) >= 0) e.status = true;
            } else if (field == 1) {
                Proto.each(d, from, to, (f, w, v, eFrom, eTo) -> {
                    if (f != 3 || w != 2) return;
                    Proto.each(d, eFrom, eTo, (mf, mw, mv, a, b) -> {
                        if (mf == 7 && mw == 0 && mv == 1) e.done = true;
                    });
                });
            }
        });
        if (e.sent) ClaudeSession.onReplySent();
        if (e.status) ClaudeSession.onReplyStatus();
        if (e.text) ClaudeSession.onReplyText();
        if (e.done) ClaudeSession.onReplyDone();
    }

    private static final class Event {
        boolean sent;
        boolean status;
        boolean text;
        boolean done;
    }

    // Packed (start << 32 | end) range of the first length-delimited field with this number, or -1.
    private static long find(byte[] d, int start, int end, int number) {
        long[] found = {-1};
        Proto.each(d, start, end, (field, wire, value, from, to) -> {
            if (found[0] < 0 && field == number && wire == 2) found[0] = ((long) from << 32) | (to & 0xffffffffL);
        });
        return found[0];
    }

    private static byte[] gunzip(byte[] data) {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * 4);
            byte[] chunk = new byte[8192];
            int r;
            while ((r = in.read(chunk)) > 0) {
                out.write(chunk, 0, r);
                if (out.size() > MAX_INFLATED) return null;
            }
            return out.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    private static final class Proto {
        interface Visitor {
            void field(int field, int wire, long value, int from, int to);
        }

        // Walks the top-level fields in [start, end); stops quietly at the first malformed byte.
        static void each(byte[] d, int start, int end, Visitor v) {
            int[] pos = {start};
            while (pos[0] < end) {
                long tag = varint(d, end, pos);
                if (tag <= 0) return;
                int field = (int) (tag >>> 3);
                int wire = (int) (tag & 7);
                if (field == 0) return;
                if (wire == 0) {
                    long value = varint(d, end, pos);
                    if (value < 0) return;
                    v.field(field, wire, value, 0, 0);
                } else if (wire == 1 || wire == 5) {
                    pos[0] += wire == 1 ? 8 : 4;
                    if (pos[0] > end) return;
                } else if (wire == 2) {
                    long len = varint(d, end, pos);
                    if (len < 0 || pos[0] + len > end) return;
                    int from = pos[0];
                    pos[0] += (int) len;
                    v.field(field, wire, 0, from, pos[0]);
                } else {
                    return;
                }
            }
        }

        private static long varint(byte[] d, int end, int[] pos) {
            long v = 0;
            for (int shift = 0; shift < 64; shift += 7) {
                if (pos[0] >= end) return -1;
                int b = d[pos[0]++] & 0xff;
                v |= (long) (b & 0x7f) << shift;
                if ((b & 0x80) == 0) return v;
            }
            return -1;
        }
    }
}
