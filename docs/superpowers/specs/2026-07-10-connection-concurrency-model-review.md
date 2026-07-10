# Review:连接并发模型设计 spec

- 评审对象:`docs/superpowers/specs/2026-07-10-connection-concurrency-model-design.md`
- 评审日期:2026-07-10
- 评审基准:Zig 0.16.0(`/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/std`),`src/server.zig`、`src/types.zig` 现状代码
- 结论:**方向正确,但有若干 API 事实性错误必须在实现前修正,否则无法编译。** 另有两处并发推理需要补强。

---

## 一、必须修正的 API 事实错误(阻断编译)

### 🔴 R1. `Group.concurrent` 的参数是 **tuple**,不是 `.{st}`

spec 写:
```
conn.worker_group.concurrent(conn.io, f, args)
```
真实签名(`Io.zig:1261`):
```zig
pub fn concurrent(g: *Group, io: Io, function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function))) ConcurrentError!void
```
`args` 的类型是 `std.meta.ArgsTuple(@TypeOf(function))`——一个**元组类型**,不是 `anytype`。调用时必须传 `.tuple` 字面量,例如:
```zig
conn.worker_group.concurrent(conn.io, runStream, .{st}) catch ...
//                                          ^^^^^^^ 这是 ArgsTuple,OK
```
spec 的 `spawnTask` 伪码把 `args` 当 `anytype` 透传(`spawnTask(conn, comptime f, args)`),然后在内部 `conn.worker_group.concurrent(conn.io, f, args)`——如果 `args` 本身就是 `.tuple`,这能编过;但 spec 没有明确 `args` 必须是 tuple 字面量,且 fallback 分支 `std.Thread.spawn(.{}, f, args)` 同样要求 `args` 是 tuple。**建议:在 `spawnTask` 签名里显式标注 `args: std.meta.ArgsTuple(@TypeOf(f))`,消除歧义。**

### 🔴 R2. `Io.Select` 没有 `race:` 语法——spec 的 `deadlineWaiter` 伪码是虚构 API

spec 写:
```
winner = Io.Select race:
    .timer : Clock.Timestamp.wait(dl, io)
    .done  : st.done_event.wait(io)
    .rearm : st.rearm_event.wait(io)
```
真实 API(`Io.zig:1367` `Io.Select(U)`)的使用方式是:
```zig
var buf: [3]U = undefined;
var sel = Io.Select(U).init(io, &buf);
try sel.concurrent(.timer, Clock.Timestamp.wait, .{ dl_ts, io });
try sel.concurrent(.done,  Event.wait, .{ &st.done_event, io });
try sel.concurrent(.rearm, Event.wait, .{ &st.rearm_event, io });
const winner = try sel.await();      // 返回 U(第一个完成者)
while (sel.cancel()) |leftover| { ... } // 回收其余两个
```
关键差异:
1. 没有 `race:` 块语法;是 `init` → 多次 `concurrent(field, fn, args)` → `await` → 循环 `cancel`。
2. `Clock.Timestamp.wait` 的第一个参数是 `Clock.Timestamp`(**带 clock 的**),不是裸 `Io.Timestamp`。spec 的 `st.deadline: ?Io.Timestamp` 存的是裸 `Io.Timestamp`(无 clock 信息),不能直接传给 `Clock.Timestamp.wait`。**必须把 deadline 存成 `Clock.Timestamp`,或在等待时用 `.withClock(.awake)` 转换。** 见 R3。
3. `Select.concurrent` 要求每个 `fn` 的返回类型匹配对应 union field。`Clock.Timestamp.wait` 和 `Event.wait` 都返回 `Cancelable!void`,所以 union 应为 `union(enum) { timer: Cancelable!void, done: Cancelable!void, rearm: Cancelable!void }`——可行,但 spec 完全没提这个 union 怎么定义。

**这是整个 Part B 的核心机制,伪码与真实 API 差距很大,必须按真实 `Select` 重写。**

### 🔴 R3. `Io.Timestamp` ≠ `Clock.Timestamp`——deadline 字段类型与 `wait` 入参不匹配

现状代码(`types.zig:204`、`server.zig`):
```zig
pub fn setDeadline(self: *Context, deadline: std.Io.Timestamp) void
st.deadline: ?Io.Timestamp = null
```
`Io.Timestamp`(`Io.zig:906`)是 `{ nanoseconds: i96 }`,**不含 clock**。
而 `Clock.Timestamp.wait`(`Io.zig:817`)需要 `Clock.Timestamp = { raw: Io.Timestamp, clock: Clock }`。

spec 的 `deadlineWaiter` 里 `.timer : Clock.Timestamp.wait(dl, io)` 传入的 `dl` 若是 `Io.Timestamp`,**类型不匹配,无法编译**。

**修正方案(二选一):**
- (A)把 `st.deadline` 改成 `?Clock.Timestamp`,`setDeadline` 的公开签名也改成 `Clock.Timestamp`(影响 `types.zig` 公开 API)。
- (B)保留 `Io.Timestamp`,在 watchdog 内部转换:`const dl_ts: Clock.Timestamp = .{ .raw = st.deadline.?, .clock = .awake };`。注意 `setDeadlineIn`(`types.zig:213`)已经用 `Io.Timestamp.now(io, .awake)`,所以 clock 固定是 `.awake`,方案 B 更小改动。

spec 在「关键 std.Io 事实」里声称 `Timeout` 支持 `.deadline`(绝对时间戳)——这没错(`Io.zig:1135`),但 `Timeout.deadline` 的类型也是 `Clock.Timestamp`,同样需要 clock。spec 遗漏了这个类型鸿沟。

---

## 二、并发推理需补强(逻辑正确性)

### 🟡 R4. `rearm_event` 的 `reset` 前置条件有 **TOCTOU 窗口**,spec 的 race-free 论证不完整

spec 论证:「`rearm_event` 仅由看门狗自身 `reset`(此刻它不在 `wait` 中,满足 `Event.reset` 的前置条件)」。

真实 `Event.reset`(`Io.zig:1867`)的文档:「Assumes that there is no pending call to `wait` or `waitUncancelable`.」

问题在于 `Select` 模型下,看门狗**不能**在 `reset` 时保证「没有 pending wait」——因为 `Select` 内部为每个 field 起一个 concurrent 任务,这些任务在 `sel.await()` 返回后、`sel.cancel()` 回收前,可能仍处于 `Event.wait` 内部(尚未响应取消)。如果看门狗在 `sel.cancel()` 循环完成**之前**调用 `rearm_event.reset()`,就违反了前置条件。

spec 的循环结构:
```
.rearm => { st.rearm_event.reset(); continue }
```
这里 `continue` 回到下一轮 `Select`,但**上一轮的 `Select` 实例的 `.done`/`.timer` 任务可能还没被 cancel 干净**。`Select` 不是「免费重置」的——每轮需要新建 `Select` 实例(或确保上一轮完全 cancel)。spec 没有展示 `Select` 的生命周期管理,这是实现时最容易出 UB 的地方。

**建议:spec 必须明确每轮循环的 `Select` 创建/销毁边界,以及 `reset` 相对于 `sel.cancel()` 循环的顺序。** 最安全的做法是:每轮 `await` 后先跑完 `cancel` 循环,再 `reset(rearm_event)`,再进下一轮。

### 🟡 R5. `done_event` 单向保证「不丢失」——在 `Select` 下成立,但 spec 的论证路径有误

spec 论证:「即使 done 与 rearm 同时发生、Select 恰好选中 rearm,`reset(rearm_event)` 只清 rearm;下一轮 Select 里仍处于 set 的 `done_event` 立即胜出」。

这个结论**正确**,但前提是 `done_event` 永不被 `reset`(单向)——spec 确实保证了。不过真实 `Event.wait` 在 `Select.concurrent` 里被包装成一个独立任务,该任务在 `done_event` 已 set 时会立即返回;`Select.await` 返回的是**第一个入队**的结果。如果 rearm 任务先完成入队,await 返回 `.rearm`,此时 done 任务可能**还没入队**(它还在 `Event.wait` 的 cmpxchg 路径上)。`sel.cancel()` 会取消它。下一轮新 `Select` 里,`done_event` 仍为 `is_set`,`Event.wait` 立即返回 → done 胜出。✅ 逻辑成立。

但 spec 完全没用这套真实机制来论证,而是用了一个抽象的「Select race」模型。**建议用真实 `Select` 语义重写这段论证**,否则实现者会按错误的模型写代码。

### 🟡 R6. `watchdog_done.wait` 在 fallback(裸 `std.Thread`)路径下的行为未验证

spec 说 fallback 路径下 `done_event`/`rearm_event`/`watchdog_done` 与 `Select`「同样成立」。但 fallback 路径里,`deadlineWaiter` 跑在一个 detach 的 `std.Thread` 上,该线程调用 `Event.wait`/`Select` 用的 `io` 是 `conn.io`(即 `Server.io`)。

需要确认:`std.Io.Threaded` 的 `Event`/`futex` 原语**是否可以由任意线程(非该 io 的 worker 线程)调用**?从 `Threaded.zig` 看,`futexWait`/`futexWake` 走的是 OS futex(`zfutex`),与线程归属无关,应该可行——但 spec 没有验证这一点。**建议补一句:fallback 线程复用 `conn.io` 调用 `Event` 原语,`Threaded` 后端的 futex 实现是线程无关的。**

---

## 三、设计层面的改进建议(非阻断)

### 🟢 R7. `active_workers` 计数与 `worker_group.await` 存在冗余——但 spec 的保留理由成立

spec 保留 `active_workers` 的理由是:把 `group.await` 闸门在 `active_workers==0` 之后,排除 add-vs-await 竞态。这个理由是**正确的**(`Group.await` 文档 `Io.zig:1279-1281` 明确要求 group 在 add 返回前不完成)。

但有一个更简单的视角:`drainWorkers` 里先 `closing=true` + 唤醒所有阻塞的 worker,然后等 `active_workers==0`。此时**所有 worker 已退出**,不可能再有 `armDeadline` 发起 `concurrent` add(因为 `armDeadline` 只在 worker 线程里调)。所以 `group.await` 此时一定立即返回(group 已空)。**`group.await` 在这个时点是 no-op,它的唯一价值是释放 group 自身的内部资源(如果有)。** spec 说得没错,但可以更直白:`group.await` 主要是为了「归还 group 资源」,不是为了等任务。

### 🟢 R8. `ConcurrencyUnavailable` 在 `Threaded` 下也会因 `concurrent_limit` 触发——spec 的 fallback 触发条件描述不完整

spec 说:「`ConcurrencyUnavailable` 仅出现在无并发能力的 Io 后端」。

真实 `Threaded.groupConcurrent`(`Threaded.zig:2261`)在 `busy_count >= concurrent_limit` 时**也**返回 `ConcurrencyUnavailable`。默认 `concurrent_limit = .unlimited`(`Threaded.zig:1592`),所以默认配置下不会触发;但如果用户配了 `concurrent_limit`,高负载下会频繁走 `std.Thread` fallback,此时**线程数可能比现状更失控**(group 任务 + fallback 线程并存)。

**建议:spec 的 Fallback 语义一节应补充:「`Threaded` 后端在 `concurrent_limit` 耗尽时也会返回 `ConcurrencyUnavailable`,此时 fallback 到裸 `std.Thread`。生产环境若设置了 `concurrent_limit`,需注意 fallback 线程不受该限额约束。」**

### 🟢 R9. 测试计划缺少 `Select` cancel 路径的覆盖

新增测试 3 项很好,但 Part B 的核心风险在 `Select` 的 `cancel` 回收(见 R4)。**建议加一个测试:**
> **deadline extend 无回归**:handler 先设近 deadline(60ms),再 extend 到很远(10s),阻塞读;断言在 10s 内**不**被中断(或被远 deadline 中断)。证明 `rearm_event` 让看门狗按更晚的 deadline 推后触发,且 `Select` cancel 路径不泄漏。

这覆盖了 tighten(测试 2)+ extend(本项)双向,以及 `Select` 多轮 cancel 的正确性。

### 🟢 R10. `runStream` defer 里 `watchdog_done.wait` 是 cancelable 的——需处理 `error.Canceled`

spec 写:
```
if (st.armed) st.watchdog_done.wait(conn.io)
```
`Event.wait` 返回 `Cancelable!void`(可能 `error.Canceled`)。在 `drainWorkers` 的取消传播环境下,这里可能收到 `error.Canceled`。spec 用的是裸 `wait` 而非 `waitUncancelable`。**建议改用 `waitUncancelable`,或 `wait(...) catch {}`——因为此刻 worker 已在退出 defer 里,不关心取消。** 现状代码用 `thread.join()`(不可取消),新设计应保持等价语义。

---

## 四、已核实正确的关键点(给实现者的信心)

| spec 声明 | 核实结果 |
|---|---|
| `Group.concurrent` 存在,返回 `ConcurrentError!void` | ✅ `Io.zig:1261` |
| `Group.await` 阻塞到全部任务结束 | ✅ `Io.zig:1282`,且 `active_workers==0` 闸门满足其 add-vs-await 安全前提 |
| `concurrent` 语义强于 `async`(后者可能内联) | ✅ `Io.zig:2362-2364` 文档明确 |
| `ConcurrencyUnavailable` 表示后端不支持并发 | ✅ `Io.zig:2352-2356`,但注意 R8 |
| `Event.set/wait/waitTimeout/reset` 存在 | ✅ `Io.zig:1780/1827/1855/1867` |
| `waitTimeout` 可能伪唤醒,需时钟复核 | ✅ `Io.zig:1825-1826` 文档明确 |
| `Timeout` 支持 `.deadline`(绝对时间戳) | ✅ `Io.zig:1135`,但类型是 `Clock.Timestamp`(见 R3) |
| `groupConcurrent` 在 `Threaded` 下多生产者安全(持 `t.mutex`) | ✅ `Threaded.zig:2256-2257` |
| `runStream` 返回 `void` 可强转为 `Cancelable!void` | ✅ `Group.concurrent` 文档 `Io.zig:1253-1254` |
| `testing.io` 是 `Io.Threaded`,支持并发 | ✅ `testing.zig:34-35` |
| 现状 `deadlineWatchdog` 10ms 轮询 + 每 deadline 一线程 | ✅ `server.zig:283-296` 核实 |

---

## 五、落地建议(优先级排序)

1. **P0(阻断)**:修正 R1/R2/R3——`spawnTask` 的 tuple 类型、`deadlineWaiter` 用真实 `Select` API 重写、deadline 字段类型与 `Clock.Timestamp` 对齐。这三项不修则无法编译。
2. **P1(正确性)**:补强 R4/R5——明确 `Select` 每轮的创建/cancel 边界与 `reset` 时序,用真实 `Select` 语义重写 race-free 论证。
3. **P2(健壮性)**:R6 补 fallback 线程下 futex 线程无关的说明;R10 把 `watchdog_done.wait` 改为 uncancelable。
4. **P3(完整度)**:R8 补 `concurrent_limit` 触发 fallback 的说明;R9 加 extend 测试。

整体评价:**架构方向(Worker 任务化 + Event 精确等待)是对的,对 `std.Io` 0.16 的核心理解也基本正确,但 Part B 的伪码停留在「概念草图」层面,与真实 `Select`/`Clock.Timestamp` API 有实质性差距。建议 spec 作者在实现前先用真实 API 写一个最小 `deadlineWaiter` 原型跑通编译,再回头修订 spec。**
