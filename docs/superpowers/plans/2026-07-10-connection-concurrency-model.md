# 连接并发模型(worker 任务化 + deadline 精确化)Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `server.zig` 的 thread-per-stream worker 改为 `Io.Group` 任务(委托给调用方 Io 后端),并用单事件 `Io.Event.waitTimeout` 取代「每 deadline 一线程 + 10ms 轮询」的看门狗,同时无损保留 deadline 的 tighten/extend 语义。

**Architecture:** 连接的 reader 线程仍单线程解析帧。每条流的 handler 通过新 helper `spawnTask` 交给 `conn.worker_group`(`Io.Group.concurrent`,`ConcurrencyUnavailable` 回退 `std.Thread`);drain 仍用现有 `active_workers` 计数,末尾再 `worker_group.await` 释放 group 资源。每条带 deadline 的流的看门狗(`deadlineWaiter`)也经 `spawnTask` 启动,阻塞在单个 `wake_event.waitTimeout(.{ .deadline })` 上:worker 完成或 `armDeadline` 重 arm 通过 `set(wake_event)` 唤醒;`done` 原子布尔区分二者,`watchdog_done` 事件替代原 `thread.join` 保证释放顺序。

**Tech Stack:** Zig 0.16.0,`std.Io`(`Io.Group` / `Io.Event` / `Io.Mutex` / `Io.Condition`),无第三方依赖。

**Spec:** `docs/superpowers/specs/2026-07-10-connection-concurrency-model-design.md`

## Global Constraints

- Zig `0.16.0`(`build.zig.zon` 的 `minimum_zig_version`);仅用 `std`,零第三方依赖。
- 传输层无关:不得引入 TLS / socket 依赖到 `server.zig` 的非测试代码。
- 所有测试用 `testing.allocator`(自带泄漏检测)+ 现有 socketpair 脚手架(`newSocketPair` / `serveRawH2OnFd` / `peerStream` / `readFrameAlloc` / `writeFrame`),不引入网络。
- `worker_group.concurrent` 是**多生产者**(reader 线程开 worker;worker 线程在 `armDeadline` 开看门狗);依赖 `std.Io.Threaded` 的 `groupConcurrent` 多线程 add 安全(已核实)。`group.await` 只在 `active_workers==0` 之后调用,排除 add-vs-await 竞态。
- 全部改动集中在 `src/server.zig`(含其 `test` 块)。其余文件不动。
- 每个任务结束跑 `zig build test --summary all`,必须 `40/40`(现状)+ 本任务新增用例全绿。

---

### Task 1: Part A — worker 走 Io.Group(spawnTask + drain）

把 worker 的启动从 `std.Thread.spawn` 改为 `conn.worker_group.concurrent`(带 `std.Thread` 回退),drain 末尾 `worker_group.await`。这是**行为保持的重构**:没有"先失败的红测试",用一个并发特征测试(characterization)+ 现有全套测试作为回归护栏。

**Files:**
- Modify: `src/server.zig`
  - `Connection` 结构(约 `:372-398`)新增 `worker_group`
  - 新增 `spawnTask`(放在 `spawnWorker` 之前,约 `:878`)
  - 重写 `spawnWorker`(约 `:878-891`)
  - 重写 `drainWorkers`(约 `:462-469`)
- Test: `src/server.zig` 末尾 `test` 区

**Interfaces:**
- Produces:
  - `Connection.worker_group: Io.Group`
  - `fn spawnTask(conn: *Connection, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f))) bool` —— 启动一个连接任务并把它计入 `active_workers`;成功返回 `true`,连回退线程都起不来时归还计数并返回 `false`。任务函数返回类型须可强转 `Io.Cancelable!void`(`void` 满足)。
- Consumes: 现有 `runStream(*H2Stream) void`、`active_workers` / `workers_mu` / `workers_cond`、`removeStream`。

- [ ] **Step 1: 写并发特征测试**

在 `src/server.zig` 末尾(`test "h2 client: multiplexes concurrent streams over one connection"` 之后)追加:

```zig
test "h2: server serves many concurrent streams via group workers and drains cleanly" {
    const client_mod = @import("client.zig");
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2EchoHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &reader.interface, &writer.interface);
    defer client.deinit();

    const N = 16;
    const Worker = struct {
        fn run(cli: *client_mod.Client, idx: usize, ok: *std.atomic.Value(u32)) void {
            var body_buf: [40]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "stream {d}", .{idx}) catch return;
            const s = cli.openStream(.{ .path = "/echo", .method = "POST" }, false) catch return;
            s.send(body, true) catch return;
            var arena_state = std.heap.ArenaAllocator.init(cli.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var got = std.ArrayList(u8).empty;
            defer got.deinit(cli.gpa);
            while (true) {
                const ev = s.readEvent(arena) catch return;
                switch (ev) {
                    .data => |d| {
                        got.appendSlice(cli.gpa, d.payload) catch return;
                        if (d.end_stream) break;
                    },
                    .headers => |h| if (h.end_stream) break,
                    .rst, .goaway => return,
                }
            }
            if (std.mem.eql(u8, got.items, body)) {
                _ = ok.fetchAdd(1, .acq_rel);
                s.close();
            }
        }
    };

    var success = std.atomic.Value(u32).init(0);
    var threads: [N]std.Thread = undefined;
    for (0..N) |i| threads[i] = std.Thread.spawn(.{}, Worker.run, .{ &client, i, &success }) catch return;
    for (threads) |th| th.join();
    try testing.expectEqual(@as(u32, N), success.load(.acquire));
}
```

- [ ] **Step 2: 跑测试确认它在当前(重构前)代码上通过 —— 建立基线覆盖**

Run: `zig build test --summary all`
Expected: PASS(此测试作为重构护栏;当前 thread-per-stream 实现也应通过。若不通过,先修测试再继续)。

- [ ] **Step 3: 实现 Part A**

3a. `Connection` 结构里,在 `active_workers: u32 = 0,` 一行之后新增字段:

```zig
    // Worker 任务组:worker/看门狗都作为任务加入,drain 时统一 await。
    worker_group: Io.Group = .init,
```

3b. 在 `fn spawnWorker` 之前新增 helper:

```zig
/// 启动一个连接任务:优先交给调用方 Io 后端(Io.Group.concurrent),从而把
/// "线程 vs 纤程" 留给后端决定;后端无并发能力时回退到 detach 的 OS 线程。
/// 成功计入 active_workers(任务自己在退出时归还);两条路径都起不来才返回 false。
/// `f` 的返回类型须可强转 Io.Cancelable!void(void 满足);`args` 显式声明为
/// `f` 的 ArgsTuple,与 Io.Group.concurrent / std.Thread.spawn 的入参要求一致。
fn spawnTask(conn: *Connection, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f))) bool {
    conn.workers_mu.lockUncancelable(conn.io);
    conn.active_workers += 1;
    conn.workers_mu.unlock(conn.io);
    conn.worker_group.concurrent(conn.io, f, args) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            const t = std.Thread.spawn(.{}, f, args) catch {
                conn.workers_mu.lockUncancelable(conn.io);
                conn.active_workers -= 1;
                conn.workers_mu.unlock(conn.io);
                return false;
            };
            t.detach();
        },
    };
    return true;
}
```

3c. 重写 `spawnWorker`(整段替换):

```zig
/// Registers worker accounting and spawns the per-stream worker task.
fn spawnWorker(conn: *Connection, st: *H2Stream) void {
    if (spawnTask(conn, runStream, .{st})) return;
    // 连回退线程都起不来:没有 worker 会接管并释放这条流,这里回收它。
    removeStream(conn, st.id);
    st.arena_state.deinit();
    conn.gpa.destroy(st);
}
```

3d. 重写 `drainWorkers`(整段替换):

```zig
    fn drainWorkers(self: *Connection) void {
        self.closing.store(true, .release);
        self.wakeSenders(); // release any window-blocked workers
        self.wakeReceivers(); // release any rx-blocked streaming workers
        self.workers_mu.lockUncancelable(self.io);
        while (self.active_workers > 0) self.workers_cond.waitUncancelable(self.io, &self.workers_mu);
        self.workers_mu.unlock(self.io);
        // 所有任务已退出(计数归零);await 释放 group 自身资源,立即返回。
        self.worker_group.await(self.io) catch {};
    }
```

- [ ] **Step 4: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 现有全部用例 + Step 1 新增的并发用例全绿(含 `testing.allocator` 无泄漏)。

- [ ] **Step 5: Commit**

```bash
git add src/server.zig docs/superpowers/specs docs/superpowers/plans
git commit -m "server: run stream workers via Io.Group instead of thread-per-stream"
```

---

### Task 2: Part B — deadline 看门狗改用单事件 waitTimeout

用 `wake_event.waitTimeout` 取代 `deadlineWatchdog` 的 10ms 轮询 + 独立线程;保留 tighten/extend 语义;看门狗经 `spawnTask` 纳入 group。新增两个用例锁定语义(及时回收 + tighten 无回归),二者在重构前后都必须通过。

**Files:**
- Modify: `src/server.zig`
  - `H2Stream` 结构(约 `:196-202`)deadline 相关字段
  - `H2Stream.armDeadline`(约 `:205-210`)
  - 删除 `deadlineWatchdog`,新增 `deadlineWaiter` + `fireDeadline`(约 `:291-309`)
  - `runStream` 的清理 `defer`(约 `:970-982`)
- Test: `src/server.zig` `test` 区(新增 3 个 handler + 3 个 test:tighten / extend / 及时回收;新增两个模块级 atomic `tighten_fired`、`extend_fired`)

**Interfaces:**
- Consumes: `spawnTask`(Task 1)、`H2Stream.conn`、`reset`/`rx_mu`/`rx_cond`、`conn.send_mu`/`send_cond`、`workers_mu`/`workers_cond`/`active_workers`。
- Produces:
  - `H2Stream` 字段:`deadline_mu: Io.Mutex`、`armed: bool`、`wake_event: Io.Event`、`watchdog_done: Io.Event`(保留 `deadline`、`timed_out`、`done`;移除 `deadline_thread`)。
  - `fn deadlineWaiter(st: *H2Stream) void`、`fn fireDeadline(st: *H2Stream) void`。

- [ ] **Step 1: 写三个语义锁定测试 + handler**

1a. 在模块级 `var saw_deadline = std.atomic.Value(bool).init(false);` 之后新增:

```zig
var tighten_fired = std.atomic.Value(bool).init(false);
var extend_fired = std.atomic.Value(bool).init(false);

/// 先设一个很远的 deadline,再收紧到很近,然后阻塞读 body。
/// 正确实现应在"更近"的 deadline 触发,而不是等到最初那个很远的。
fn tightenDeadlineHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(10 * std.time.ns_per_s); // 远
    ctx.setDeadlineIn(80 * std.time.ns_per_ms); // 收紧到近
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = br.read(&tmp) catch |err| switch (err) {
                error.DeadlineExceeded => {
                    tighten_fired.store(true, .release);
                    return err;
                },
                else => return err,
            };
            if (n == 0) break;
        }
    }
    return error.TestUnexpectedResult;
}

/// 先设一个很近的 deadline,再放宽到很远,然后阻塞读 body。
/// 正确实现应按"更远"的 deadline 推后触发:短时间内不得中断。
fn extendDeadlineHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(80 * std.time.ns_per_ms); // 近
    ctx.setDeadlineIn(10 * std.time.ns_per_s); // 放宽到远
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = br.read(&tmp) catch |err| switch (err) {
                error.DeadlineExceeded => {
                    extend_fired.store(true, .release);
                    return err;
                },
                else => return err,
            };
            if (n == 0) break;
        }
    }
    return error.TestUnexpectedResult;
}

/// 设一个很远的 deadline 后立即完成 —— 看门狗必须被及时回收,不能空等到 deadline。
fn armLongDeadlineHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(10 * std.time.ns_per_s);
    try ctx.res.send(200, "text/plain", "ok");
}
```

1b. 在 `test` 区末尾新增两个测试:

```zig
test "h2: tightening a deadline fires at the earlier time (no regression)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = tightenDeadlineHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    // 不带 END_STREAM → handler 阻塞在 body_reader 直到(收紧后的)deadline 触发。
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);

    // 收紧后的 deadline 是 80ms;等到远超它、但远低于 10s 的时刻。
    // 若退化成只认第一个(10s)deadline,此刻不会触发 → 测试失败。
    Io.sleep(testing.io, .{ .nanoseconds = 400 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(tighten_fired.load(.acquire));
}

test "h2: extending a deadline pushes the timeout later (no regression)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = extendDeadlineHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);

    // 放宽后的 deadline 是 10s;等到远超最初的 80ms、但远低于 10s 的时刻。
    // 正确实现此刻**不应**触发(看门狗按更晚的 deadline 重等);
    // 若退化成只认第一个(80ms)deadline,此刻已误触发 → 测试失败。
    Io.sleep(testing.io, .{ .nanoseconds = 400 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!extend_fired.load(.acquire));
}

test "h2: deadline watchdog is reclaimed promptly when the handler finishes early" {
    const fds = try newSocketPair();
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = armLongDeadlineHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });

    // shut 守卫:任一 try 失败时经 defer 完成 close+join;成功路径显式 close+join 后置 true。
    var shut = false;
    defer if (!shut) {
        _ = c.close(fds[1]);
        t.join();
    };

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    // END_STREAM:无 body,handler 立即返回。
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);

    // 读到响应的 END_STREAM,确认 handler 已完成。
    var saw_end = false;
    while (!saw_end) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        defer f.deinit(testing.allocator);
        if ((f.header.flags & flag_end_stream) != 0 and
            (f.header.ftype == .data or f.header.ftype == .headers)) saw_end = true;
    }

    // 关闭 client 端 → 服务端 readLoop EOF → drainWorkers。计时 close+join。
    // 若看门狗只会 sleep 到 10s deadline,worker 会卡在清理 defer 里 ~10s,join 随之被拖住。
    const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
    shut = true;
    _ = c.close(fds[1]);
    t.join();
    const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 2000);
}
```

- [ ] **Step 2: 跑测试确认三个新用例在当前(重构前)代码上通过 —— 证明它们捕捉的是既有语义**

Run: `zig build test --summary all`
Expected: PASS —— 当前 10ms 轮询看门狗既支持 tighten/extend(每轮重读 `st.deadline`)也及时回收(轮询到 `done` 后 join),故三个用例现在就应绿。(若某个不绿,说明测试写错,先修测试。)

- [ ] **Step 3: 实现 Part B**

3a. `H2Stream` 结构里,把现有 deadline 相关字段:

```zig
    deadline: ?Io.Timestamp = null,
    timed_out: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    deadline_thread: ?std.Thread = null,
```

替换为:

```zig
    /// Per-RPC deadline(绝对 awake-clock 时间戳),`deadline_mu` 保护读写。
    deadline: ?Io.Timestamp = null,
    deadline_mu: Io.Mutex = .init,
    timed_out: std.atomic.Value(bool) = .init(false),
    /// worker 退出时置 true(单向,永不清零);看门狗据此区分 "worker 完成" 与 "重 arm"。
    done: std.atomic.Value(bool) = .init(false),
    /// 是否已启动看门狗(仅 worker 线程访问,无需加锁)。
    armed: bool = false,
    /// 合并唤醒:worker 完成(先置 done)或 armDeadline 重 arm 时 set;看门狗处理后 reset。
    wake_event: Io.Event = .unset,
    /// 看门狗退出前 set;worker 释放 st 前 wait 它(替代 thread.join)。
    watchdog_done: Io.Event = .unset,
```

3b. 重写 `armDeadline`(整段替换):

```zig
    /// 设定/收紧/放宽 per-RPC deadline;首次调用启动看门狗,之后唤醒它重读。
    /// 只由该流的 worker 线程(handler → ctx.setDeadline)调用。
    fn armDeadline(self: *H2Stream, deadline: Io.Timestamp) void {
        const conn = self.conn;
        self.deadline_mu.lockUncancelable(conn.io);
        self.deadline = deadline; // 先写 deadline(真相来源)
        self.deadline_mu.unlock(conn.io);
        if (!self.armed) {
            self.armed = true;
            if (!spawnTask(conn, deadlineWaiter, .{self})) self.armed = false;
        } else {
            self.wake_event.set(conn.io); // 唤醒既有看门狗重读(可能更早的)deadline
        }
    }
```

3c. 删除整个 `fn deadlineWatchdog(st: *H2Stream) void { ... }`,替换为:

```zig
/// 触发超时:置位并唤醒任何阻塞在 rx / send 的流 I/O(与原看门狗一致)。
fn fireDeadline(st: *H2Stream) void {
    const conn = st.conn;
    st.timed_out.store(true, .release);
    st.reset.store(true, .release);
    st.rx_mu.lockUncancelable(conn.io);
    st.rx_cond.broadcast(conn.io);
    st.rx_mu.unlock(conn.io);
    conn.send_mu.lockUncancelable(conn.io);
    conn.send_cond.broadcast(conn.io);
    conn.send_mu.unlock(conn.io);
}

/// 看门狗任务:阻塞在单个 wake_event 上直到 deadline 到点、worker 完成、或重 arm。
/// 无轮询、不派生子任务(waitTimeout 底层是一次 futexWaitTimeout)。
fn deadlineWaiter(st: *H2Stream) void {
    const conn = st.conn;
    while (true) {
        st.deadline_mu.lockUncancelable(conn.io);
        const dl = st.deadline.?;
        st.deadline_mu.unlock(conn.io);

        st.wake_event.waitTimeout(conn.io, .{ .deadline = dl.withClock(.awake) }) catch |err| switch (err) {
            error.Timeout => {
                // 计时到点或伪唤醒:用时钟复核当前 deadline。
                const now = Io.Timestamp.now(conn.io, .awake);
                st.deadline_mu.lockUncancelable(conn.io);
                const cur = st.deadline.?;
                st.deadline_mu.unlock(conn.io);
                if (now.nanoseconds >= cur.nanoseconds) {
                    fireDeadline(st);
                    break;
                }
                continue; // 伪唤醒 / deadline 被 extend → 用最新 dl 再等
            },
            else => break, // error.Canceled → 退出,不触发
        };

        // wake_event 被 set:worker 完成 或 重 arm。
        if (st.done.load(.acquire)) break; // worker 完成 → 不触发
        st.wake_event.reset(); // 认领本次唤醒(此刻不在 wait 中,满足 reset 前置条件)
        if (st.done.load(.acquire)) break; // 复查:与 reset 竞争的 done 不丢
        // 否则是重 arm(tighten/extend)→ 回到循环用新 dl
    }
    st.watchdog_done.set(conn.io); // 看门狗对 st 的最后一次触碰
    // 看门狗也是 spawnTask 计入的任务,退出前归还计数(只碰 conn):
    conn.workers_mu.lockUncancelable(conn.io);
    conn.active_workers -= 1;
    conn.workers_cond.signal(conn.io);
    conn.workers_mu.unlock(conn.io);
}
```

3d. `runStream` 的清理 `defer` 里,把现有开头两行:

```zig
        st.done.store(true, .release);
        if (st.deadline_thread) |w| w.join();
```

替换为:

```zig
        st.done.store(true, .release); // 单向置位,先于 set
        if (st.armed) {
            st.wake_event.set(conn.io); // 唤醒看门狗观察 done
            // 必须 uncancelable:若 wait 因取消提前返回,看门狗可能仍在触碰 st,
            // 之后 free 会 use-after-free。等价于旧实现的 thread.join()。
            st.watchdog_done.waitUncancelable(conn.io);
        }
```

- [ ] **Step 4: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 现有 deadline 用例(`per-RPC deadline aborts a blocked body read`)+ Task 1 用例 + Step 1 两个新用例全绿,`testing.allocator` 无泄漏。

- [ ] **Step 5: Commit**

```bash
git add src/server.zig
git commit -m "server: replace polling deadline watchdog with a single wake_event waitTimeout"
```

---

## Self-Review

**Spec coverage:**
- Part A(worker→Io.Group + spawnTask + drain via counter then await)→ Task 1 ✓
- Part B(移除 deadline_thread、`wake_event`/`done`/`watchdog_done`/`deadline_mu`/`armed`、`armDeadline` 重写、`deadlineWaiter` + `fireDeadline`、`runStream` defer 握手)→ Task 2 ✓
- Fallback(`ConcurrencyUnavailable`→`std.Thread`)→ Task 1 `spawnTask` ✓
- 多生产者 / add-vs-await 闸门 → Global Constraints + Task 1 `drainWorkers`(await 在 `active_workers==0` 之后)✓
- 测试:及时回收 + tighten 无回归 + extend 无回归 + drain/无泄漏 → Task 2 三个新用例 + Task 1 并发用例 + 全套 `testing.allocator` ✓

**Placeholder scan:** 无 TBD/TODO;每个改动步骤给出完整可粘贴代码与整段替换目标。

**Type consistency:**
- `spawnTask(conn, f, args) bool` 在 Task 1 定义,Task 2 `armDeadline` 用 `spawnTask(conn, deadlineWaiter, .{self})` 一致。
- `worker_group: Io.Group`(Task 1)/ `worker_group.await` / `worker_group.concurrent` 一致。
- `wake_event`/`watchdog_done`/`done`/`armed`/`deadline_mu` 在 Task 2 结构定义,并被 `armDeadline`/`deadlineWaiter`/`runStream` 一致引用;`fireDeadline` 名称一致。
- `dl.withClock(.awake)` 把 `Io.Timestamp` 转为 `waitTimeout` 需要的 `Clock.Timestamp`(已核实类型)。
