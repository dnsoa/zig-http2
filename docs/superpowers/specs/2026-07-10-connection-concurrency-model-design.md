# 设计:连接并发模型 — worker 任务化 + deadline 精确化

- 日期:2026-07-10
- 对应 review 项:#4(thread-per-stream + 每 deadline 一线程 + 10ms 轮询)
- 目标库:`zig-http2`(gRPC / 自研 CDN 的 HTTP/2 底座)

## 背景与动机

当前 `server.zig` 的并发模型:

- `serveConn` 在调用方线程上运行,是唯一的 **reader**(帧解析 + HPACK 解码)。
- 每个 HEADERS 完成 → `spawnWorker` → `std.Thread.spawn(runStream)` **detach**,一个 OS 线程跑一条流的 handler。
- 每条带 deadline 的流 → `armDeadline` → 再 `std.Thread.spawn(deadlineWatchdog)`,该看门狗**每 10ms 轮询**比较 `now` 与 `deadline`。

问题:

1. **线程爆炸**:线程数 = 连接数 + 活跃流数 + 带 deadline 的流数。CDN / 高 QPS gRPC 服务端(默认每连接 128 并发流)下不可扩展,也没用上 `std.Io` 的异步模型。
2. **轮询浪费 + 粒度粗**:每 deadline 一条线程每 10ms 唤醒一次;deadline 精度被限制在 10ms。gRPC 每次调用都带 deadline,等于每次调用多一条轮询线程。

## 目标

1. **Worker**:`std.Thread.spawn` per-stream → `Io.Group.concurrent`,把「线程 vs 纤程」的选择交给调用方提供的 `Io` 后端。线程后端(`std.Io.Threaded`)行为与现状等价;未来纤程 / 事件循环后端下,每条流是廉价 green task,本库无需改动。
2. **Deadline**:去掉「每 deadline 一线程 + 10ms 轮询」,改为看门狗阻塞在单个 `Io.Event.waitTimeout(.{ .deadline })` 上(worker 完成 / 重 arm 通过 `set` 该事件唤醒);worker 提前完成时立即被唤醒回收,不再空等到 deadline,并**无损保留** deadline 的 tighten/extend 语义。

## 关键 std.Io 事实(已在 0.16 源码核实)

- `Io.Group`:`concurrent(io, fn, args) ConcurrentError!void` 加入一个 fire-and-forget 任务;**每个任务返回时其资源即释放**,因此「长生命周期 group 反复加任务」不构成泄漏;`Group.await(io)` 阻塞直到全部任务结束。→ 天然替代手写的 `active_workers`/`workers_cond` drain。
- `io.concurrent` 语义强于 `io.async`(后者可能内联同步执行,会阻塞 reader),故 worker 必须用 `concurrent`。`ConcurrencyUnavailable` 表示后端不支持并发。
- `groupConcurrent`(`Io/Threaded.zig:2238`)在运行时全局 `t.mutex` 下入队 + 原子更新 group 状态 → **多生产者(多线程并发 add)安全**。
- `Io.Event`:`set(io)`(单向置位,`reset` 前保持)/ `wait(io) Cancelable!void` / `reset()`(要求调用时无 pending `wait`;与并发 `set`/`isSet`/`reset` 兼容)。
- `Io.Event.waitTimeout(io, Timeout) WaitTimeoutError!void`(`error.Timeout || Cancelable`):等到事件被 `set` 或超时;底层是单次 `io.futexWaitTimeout`,**不派生额外任务/线程**。
- `Timeout` 联合体 `.deadline` 取 `Clock.Timestamp`;`Io.Timestamp` 经 `withClock(.awake)` 转得。
- `waitTimeout` 的 `error.Timeout` **可能是伪唤醒**——deadline 触发前必须用时钟复核 `now >= deadline`。

## Part A — Worker 任务化

### Connection 变化
- 新增 `worker_group: Io.Group = .init`。
- **保留** `active_workers` / `workers_mu` / `workers_cond`,作为**统一 drain 计数**,同时覆盖 group 任务与 fallback 线程两条路径。

### 新 helper `spawnTask`(worker 与 watchdog 共用)
```
fn spawnTask(conn, comptime f, args) bool:
    conn.workers_mu.lock(); conn.active_workers += 1; conn.workers_mu.unlock()
    conn.worker_group.concurrent(conn.io, f, args) catch |e| switch (e) {
        error.ConcurrencyUnavailable => {
            // 退化后端(无并发能力)——用真实 OS 线程兜底,功能等价现状。
            const t = std.Thread.spawn(.{}, f, args) catch {
                conn.workers_mu.lock(); conn.active_workers -= 1; conn.workers_mu.unlock()
                return false
            }
            t.detach()
        },
    }
    return true
```
- `spawnWorker` 改为调用 `spawnTask(conn, runStream, .{st})`;返回 false(连兜底线程都起不来)时,回滚并 `removeStream`(沿用现有逻辑)。
- `runStream` 退出 defer 中 `active_workers -= 1; workers_cond.signal` 保持不变。
- `runStream` 签名保持 `fn(*H2Stream) void`——`void` 可强制转换为 `Group` 要求的 `Cancelable!void`。

### drainWorkers
```
closing = true
wakeSenders(); wakeReceivers()
workers_mu.lock(); while (active_workers > 0) workers_cond.wait(); workers_mu.unlock()   // 覆盖两条路径
conn.worker_group.await(conn.io) catch {}    // 释放 group 自身资源;此刻任务已全部结束,立即返回
```
`conn.deinit` 不再需要触碰 group(已 await)。

## Part B — Deadline 精确化(单事件 waitTimeout)

**保留的可观察语义(不回归)**:现有 `Context.setDeadline` / `setDeadlineIn`(`server.zig:204-208`)允许**首次 set 之后再收紧(tighten)或放宽(extend)** deadline,并让超时相应提前 / 推后触发。中间件、拦截器、业务代码常做 `min(incoming, local budget)` 式收紧,因此这是 API 的公开契约,新设计必须无损保留 —— 不得降级成「往前缩不保证提前触发」。

**为什么用 `Event.waitTimeout` 而非 `Io.Select` 竞速**:`std.Io.Threaded` 的 `concurrent_limit` 默认 `.unlimited`,`Io.Select` 的每个竞速分支都经 `io.concurrent` 落到**一条真实 OS 线程**。用 Select 竞速「计时器 + done + rearm」= 每条带 deadline 的流每轮多起约 3 条线程,而 gRPC 每次调用都带 deadline —— 这会**放大**而非消除线程数,与 Part B 目标相悖。`Event.waitTimeout` 底层是 `io.futexWaitTimeout` 单次阻塞等待,**不派生额外任务/线程**:看门狗自身是 1 个任务,阻塞在一个 futex 上。故采用单个「唤醒事件」+ `waitTimeout` 方案。

### H2Stream 变化
- 移除 `deadline_thread`。
- `wake_event: Io.Event = .unset`——**合并唤醒**:worker 完成(先置 `done=true` 再 `set`)或 `armDeadline` 重 arm 时 `set`;看门狗处理后 `reset`。
- 保留现有 `done: std.atomic.Value(bool)`——用于在 `wake_event` 醒来后区分「worker 完成」与「重 arm」。**单向**:一经置 true 永不清零。
- `watchdog_done: Io.Event = .unset`——看门狗退出前 `set`;worker 释放 `st` 前 `wait` 它(替代原 `thread.join`,保证看门狗不在 `st` 释放后 use-after-free)。
- `deadline: ?Io.Timestamp` 的读写用小锁 `deadline_mu` 保护(顺带消除当前 watchdog 读 / worker 写 `st.deadline` 的 data race)。
- `armed: bool`——仅 worker 线程访问(见下),无需加锁。
- `timed_out` / `reset` 语义不变。
- `Io.Timestamp`(纳秒 `i96`)转 `waitTimeout` 所需的绝对 `Clock.Timestamp`:`dl.withClock(.awake)`。

### armDeadline(dl)（仅在 worker 线程调用:handler → ctx.setDeadline → h2SetDeadline)
```
deadline_mu.lock(); st.deadline = dl; deadline_mu.unlock()   // 先写 deadline(真相来源)
if (!st.armed):
    st.armed = true
    if (!spawnTask(conn, deadlineWaiter, .{st})): st.armed = false   // spawn 失败 → 无看门狗
else:
    st.wake_event.set(conn.io)   // 唤醒既有看门狗重读(可能更早的)deadline
```
`setDeadline` 对同一 `st` 只由该流的单个 worker 线程发起,故 `armed` 无需加锁;`deadline` 用 `deadline_mu` 与看门狗线程同步。**必须先写 `deadline` 再 `set(wake_event)`**,这样看门狗一旦观察到唤醒就一定能读到新值。

### deadlineWaiter(st)
```
loop:
    const dl = load(st.deadline)                              // 加锁读
    st.wake_event.waitTimeout(conn.io, .{ .deadline = dl.withClock(.awake) }) catch |e| switch (e) {
        error.Timeout => {                                    // 计时到点,或伪唤醒
            if (now.nanoseconds >= load(st.deadline).nanoseconds) { fire(); break }  // 复核:防伪唤醒
            else continue                                     // 伪唤醒 / 被 extend → 用最新 dl 再等
        },
        else => break,                                        // Canceled → 退出
    }
    // waitTimeout 正常返回 = wake_event 被 set(worker 完成 或 重 arm):
    if (st.done.load(.acquire)) break                         // worker 完成 → 不触发
    st.wake_event.reset()                                     // 认领本次唤醒
    if (st.done.load(.acquire)) break                         // 复查:与 reset 竞争的 done 不丢
    // 否则是重 arm(tighten/extend)→ 回到循环用新 dl
st.watchdog_done.set(conn.io)                                 // 看门狗对 st 的最后一次触碰(此后 worker 可 free st)
// 看门狗也是经 spawnTask 计数的任务,退出前归还计数(只碰 conn):
conn.workers_mu.lock(); conn.active_workers -= 1; conn.workers_cond.signal(); conn.workers_mu.unlock()
```
`fire()` = 现有逻辑:`timed_out=true; reset=true;` 广播 `rx_cond` 与 `send_cond`。

**为什么 race-free**(done 与 reset 竞争):worker 顺序为 `done.store(release)` → `wake_event.set(release)`。看门狗醒来后先查 `done`;若为 false 则 `reset(wake_event)`,再**复查** `done`——
- 若 worker 的 `done+set` 落在 reset 与复查之间 → 复查读到 true,退出;
- 若落在复查之后 → `wake_event` 被重新置 set,下一轮 `waitTimeout` 立即返回(非 Timeout)→ 再查 `done` 为 true → 退出。
两种交错都不会丢 done 唤醒,故不会挂死到 deadline。`wake_event.reset` 仅由看门狗在**非 `wait` 态**下调用,满足 `Event.reset` 前置条件;与 worker/arm 的并发 `set` 兼容。

**计数约定**:`spawnTask` 为它启动的**每个**任务(`runStream` 与 `deadlineWaiter`)`active_workers += 1`;两者退出前各自负责一次 `active_workers -= 1` + `signal`。`st.watchdog_done.set` 必须是看门狗对 `st` 的最后一次访问;其后的计数归还只碰 `conn`(生命周期长于 `st`),故安全。

### runStream defer(释放前收尾)
```
st.done.store(true, .release)                          // 单向置位(先于 set)
if (st.armed) {
    st.wake_event.set(conn.io)                         // 唤醒看门狗观察 done
    st.watchdog_done.waitUncancelable(conn.io)         // 等看门狗退出后再 free st
}
... removeStream / arena.deinit / destroy / active_workers-- ...
```
仅当 arm 过看门狗才 `set + wait`;未 arm 直接跳过。**必须 `waitUncancelable`**:若用可取消的 `wait` 且被取消提前返回,看门狗可能仍在触碰 `st`,随后 free 即 use-after-free —— 等价于旧实现不可取消的 `thread.join()`。

### 收益
- 无轮询;deadline 精度不再受 10ms 限制;看门狗阻塞在单个 futex,不派生额外线程。
- **tighten/extend 均无损保留**:重 arm 通过 `wake_event` 立即唤醒看门狗重读,收紧时更早触发,与现状一致。
- worker 早于 deadline 完成时,看门狗被 `wake_event` 立即唤醒退出,不再空等到 deadline。
- 看门狗也是 group 任务 → 纤程后端下 gRPC 每次调用的 deadline 不再各占一条 OS 线程。

## Fallback 语义
`ConcurrencyUnavailable` 出现于两种情况:(1)无并发能力的 Io 后端(对多路复用服务器本就不可用);(2)`std.Io.Threaded` 在 `busy_count >= concurrent_limit` 时也会返回它(`Threaded.zig:2261`)。默认 `concurrent_limit = .unlimited`,不触发;但**若生产环境显式设置了 `concurrent_limit`,高负载下会回退到裸 `std.Thread`,而 fallback 线程不受该限额约束**(需知晓,否则以为限额能封顶线程数)。两种情况下都退化为 `std.Thread.spawn`,功能等价于现状。

`wake_event`/`watchdog_done` 与 `waitTimeout` 均为后端无关原语:`std.Io.Threaded` 的 `Event`/`futex` 走 OS futex(`futexWait*`/`futexWake`),与调用线程归属无关,故 fallback 里由 detach 的 `std.Thread` 复用 `conn.io` 调用它们是安全的。fallback 路径下 tighten/extend 与生命周期语义**同样成立**(不因 fallback 而降级)。

## 测试

复用并必须继续通过:
- gRPC unary echo、多路复用并发流、GOAWAY 优雅 drain、per-RPC deadline 中断阻塞读、finish() 幂等。

新增:
1. **看门狗及时回收**:设一个很长的 deadline(如 10s),handler 立即完成;断言连接 teardown 在远小于 deadline(如 <2s)内返回——证明 `wake_event` 提前唤醒了看门狗(朴素的 sleep-until-deadline 会卡满 10s)。
2. **deadline tighten 无回归(防守本次 review 的高优先级项)**:handler 先设一个远的 deadline(如 10s),再收紧到很近(如 60ms)后阻塞读 body;断言在 ≈60ms(而非 10s)内以 `DeadlineExceeded` 中断。证明 `wake_event` 重 arm 让看门狗按更早的 deadline 提前触发。
3. **drain 覆盖 group 任务 + 无泄漏**:并发多条流,GOAWAY 后 `drainWorkers` 正常返回;用 `testing.allocator` 检漏。

## 线程归属与 worker_group 并发安全(修订)
`worker_group` 上有两类调用者,不能笼统说"都在 reader 线程":

- **`concurrent`(add)**:
  - `spawnWorker` → 由 **reader 线程** 发起(新流);
  - `armDeadline` → 由 **worker 线程** 发起(handler 调 `setDeadline`,见 `server.zig:283-285`、`server.zig:999-1001`)。
  → 因此 `worker_group.concurrent` 是**多生产者**。这要求 `groupConcurrent` 多线程并发 add 安全。已核实 `std.Io.Threaded`(`Io/Threaded.zig:2238`)在运行时全局 `t.mutex` 下完成入队、`group.status()` 用原子 `fetchAdd`,**多生产者安全**;单线程后端返回 `ConcurrencyUnavailable` → 走 `std.Thread` fallback。未来自定义后端需保证同一 add-vs-add 安全性(文档约束)。
- **`await`(drain)**:仅 **reader 线程** 在 `drainWorkers` 调用。`Io.Group.await` 与并发 add 的安全前提是"group 在 add 返回前不会完成";我们把 `group.await` **闸门在 `active_workers==0` 之后**:此时不再有 worker 运行,也就不会有 `armDeadline` 并发 add,从根上排除 add-vs-await 竞态。(这也是保留 `active_workers` 计数的理由之一。)

## 风险与缓解
- `std.Io` 0.16 的 `Group` / `Event` 较新:`waitTimeout` 的伪唤醒已用**时钟复核**处理;`done` 单向、`wake_event` 仅看门狗 reset + 复查,done/rearm 竞态已在上文论证为 race-free。
- `groupConcurrent` 多生产者安全性目前依据 `std.Io.Threaded` 源码;若换后端需复核(见上节)。
- 增量落地:先 Part A(worker→group)跑通全部测试,再 Part B(deadline)。TDD:先写新增测试(红),再改实现(绿)。
