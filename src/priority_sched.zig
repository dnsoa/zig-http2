//! Shared generic 8-bucket intrusive RFC 9218 outbound `DATA` scheduler
//! (`PriorityScheduler(Node)`). Zero heap allocations; `O(1)` enqueue, remove,
//! round-robin rotation (`incremental = true`), urgency preemption (`0..7`),
//! and targeted per-stream condition wakeup.

const std = @import("std");
const Io = std.Io;
const proto = @import("proto.zig");

pub fn PriorityScheduler(comptime Node: type) type {
    return struct {
        const Self = @This();

        heads: [8]?*Node = @splat(null),
        tails: [8]?*Node = @splat(null),
        count: u32 = 0,

        pub fn pushTail(self: *Self, st: *Node) void {
            if (st.in_sched) return;
            const u: usize = st.priority.urgency;
            st.sched_bucket = st.priority.urgency;
            st.sched_prev = self.tails[u];
            st.sched_next = null;
            if (self.tails[u]) |tail| {
                tail.sched_next = st;
            } else {
                self.heads[u] = st;
            }
            self.tails[u] = st;
            st.in_sched = true;
            self.count += 1;
        }

        pub fn remove(self: *Self, st: *Node) void {
            if (!st.in_sched) return;
            const u: usize = st.sched_bucket;
            if (st.sched_prev) |prev| {
                prev.sched_next = st.sched_next;
            } else {
                self.heads[u] = st.sched_next;
            }
            if (st.sched_next) |next| {
                next.sched_prev = st.sched_prev;
            } else {
                self.tails[u] = st.sched_prev;
            }
            st.sched_prev = null;
            st.sched_next = null;
            st.in_sched = false;
            self.count -= 1;
        }

        pub fn rotateTail(self: *Self, st: *Node) void {
            if (!st.in_sched) return;
            const u: usize = st.sched_bucket;
            if (self.tails[u] == st) return;
            self.remove(st);
            self.pushTail(st);
        }

        pub fn top(self: *const Self) ?*Node {
            if (self.count == 0) return null;
            for (self.heads) |head_opt| {
                if (head_opt) |h| return h;
            }
            return null;
        }

        pub fn wakeNext(self: *const Self, io: Io, conn_send_window: i64) void {
            if (conn_send_window <= 0) return;
            if (self.top()) |t| {
                t.send_cond.broadcast(io);
            }
        }

        pub fn leaveAndWake(self: *Self, io: Io, st: *Node, conn_send_window: i64) void {
            if (!st.in_sched) return;
            self.remove(st);
            self.wakeNext(io, conn_send_window);
        }

        pub fn reprioritize(self: *Self, io: Io, st: *Node, new_prio: proto.StreamPriority, conn_send_window: i64) void {
            st.priority = new_prio;
            if (st.in_sched and st.sched_bucket != new_prio.urgency) {
                self.remove(st);
                self.pushTail(st);
                self.wakeNext(io, conn_send_window);
            }
        }

        pub fn canSendImmediate(self: *const Self, st: *const Node, enabled: bool) bool {
            if (!enabled or self.count == 0) return true;
            const cur_top = self.top() orelse return true;
            return st.priority.urgency < cur_top.priority.urgency;
        }
    };
}

test "PriorityScheduler orders by urgency, rotates incremental tails, and reprioritizes dynamically" {
    const testing = std.testing;
    const DummyNode = struct {
        id: u31,
        priority: proto.StreamPriority = .{},
        sched_prev: ?*@This() = null,
        sched_next: ?*@This() = null,
        in_sched: bool = false,
        sched_bucket: u3 = 3,
        send_cond: Io.Condition = .init,
    };

    var sched: PriorityScheduler(DummyNode) = .{};
    var n_low: DummyNode = .{ .id = 1, .priority = .{ .urgency = 6 } };
    var n_i1: DummyNode = .{ .id = 3, .priority = .{ .urgency = 2, .incremental = true } };
    var n_i2: DummyNode = .{ .id = 5, .priority = .{ .urgency = 2, .incremental = true } };

    sched.pushTail(&n_low);
    sched.pushTail(&n_i1);
    sched.pushTail(&n_i2);
    try testing.expectEqual(@as(u32, 3), sched.count);
    try testing.expectEqual(@as(u31, 3), sched.top().?.id);

    sched.rotateTail(&n_i1);
    try testing.expectEqual(@as(u31, 5), sched.top().?.id);

    // Dynamically promote `n_low` from urgency 6 to urgency 0 -> becomes new top!
    sched.reprioritize(testing.io, &n_low, .{ .urgency = 0, .incremental = false }, 65535);
    try testing.expectEqual(@as(u31, 1), sched.top().?.id);

    sched.leaveAndWake(testing.io, &n_low, 65535);
    try testing.expectEqual(@as(u31, 5), sched.top().?.id);
}
