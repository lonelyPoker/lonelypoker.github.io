# **asyncio**

#### asyncio.run
```python
# asyncio.run(coro, *, debug=False)
# @param coro:coroutine object
# @pararm debug: 如果debug=True，事件循环将以调试模式运行

import asyncio

async def main():
    print("hello")
    print("world")

asyncio.run(main())

```

#### asyncio.sleep
```python
# asyncio.sleep(delay, result=None, *, loop=None)
# @pararm delay: 如果debug=True，事件循环将以调试模式运行
# @return Awaitable object
# @description:挂起当前任务，允许其他任务运行

async def main():
    print("hello")
    await asyncio.sleep(1)
    print("world")

asyncio.run(main())
```

#### asyncio.create_task
```python
# asyncio.create_task(coro)
# @param coro:coroutine object
# @return Task object
# @description:将协程对象生成一个Task对象
# @Warning:推荐使用create_task封装协程await,不要直接await原生协程，

async def main():
    task_1 = asyncio.create_task(
        say_after(1, 'hello')
    )
    task_2 = asyncio.create_task(
        say_after(2,'world'))
    print(f"started at {time.strftime('%X')}")
    await task_1
    await task_2
    print(f"finished at {time.strftime('%X')}")


asyncio.run(main())

```


#### asyncio.ensure_future
```python
# asyncio.ensure_future(coro_or_future, *, loop=None)
# @param coro_or_future:coroutine、Future、Awaitble object
# @return Future object
# @description:将协程对象生成一个Future对象

async def main():
    ef = asyncio.ensure_future(asyncio.sleep(3))
    await ef

```


#### asyncio.get_event_loop
```python
# asyncio.get_event_loop()
# @return AbstractEventLoop object
```
#### asyncio.new_event_loop
```python
# asyncio.new_event_loop()
# @return AbstractEventLoop object
# @description:生成一个新的AbstractEventLoop object
```

#### asyncio.set_event_loop
```python
# asyncio.set_event_loop(loop)
# @param loop:AbstractEventLoop object
# @description:将指定的loop替换默认的事件循环

def start_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

```
#### asyncio.as_completed
```python
# asyncio.as_completed(fs, *, loop=None, timeout=None)
# @param fs: coroutines
# @return:coroutines
# @description:在as_completed返回的coroutines中,优先返回状态为done的coroutine.
async  def main():
    for fs in asyncio.as_completed([foo(i) for i in range(10)]):
        res =  await asyncio.create_task(fs)
        print(res)

```
#### asyncio.wait

```python
# asyncio.wait(fs, *, loop=None, timeout=None, return_when=ALL_COMPLETED)
# @param fs: coroutines
# @return:dones(Iterable[Future]),pendings(Iterable[Future])
# @description:asyncio.wait() result返回两种不同状态的future，状态为done的future在dones,状态为pending的future在pendings
async def main():
    done_set:Iterable[Future] = set()
    pending_set:Iterable[Future] = set()
    # done,pending = await asyncio.wait({foo(100)},timeout=1)
    done_set,pending = await asyncio.wait({foo(100),foo(10000),foo(10000)})
    for d in done_set:
        print(d.result())

```

#### asyncio.gather
```python
# asyncio.gather(*coros_or_futures, loop=None, return_exceptions=False)
# param coros_or_futures:unpacking coroutines (解包协程列表)
# @return:返回与协程列表相对应的结果集

async def foo(value):
    await asyncio.sleep(1)
    return len(range(value))

async def gather_main():
    result_list:List[Any] = await asyncio.gather(foo(100),foo(10000),foo(1000000))
    for ele in result_list:
        print(ele)

asyncio.run(gather_main())

```

#### asyncio.shield
```python
# asyncio.shield(arg, *, loop=None)
# param arg:coroutine
# return: coroutine 函数返回的结果
# description：asyncio.shield保护协程arg不会被取消,除非取消包含它的协程，否则)不会取消运行的任务
async def main():
    res = await asyncio.shield(say_later(1,'hahaha'))

```

#### asyncio.wait_for

```python
# asyncio.wait_for(fut, timeout, *, loop=None)
# param fut:Coroutine,Future
# param timeout:秒
# return Future
# description:等待单个Future或协程完成超时。 Coroutine将包含在Task中。返回Future或协程的结果。发生超时时，它会取消该任务并引发TimeoutError。要避免任务取消，请将其包装在shield（）中。如果取消等待，则任务也会被取消。
```

#### asyncio.open_connection
#### asyncio.start_server
#### asyncio.run_coroutine_threadsafe
#### asyncio.create_subprocess_shell
#### asyncio.create_subprocess_exec
#### asyncio.WindowsProactorEventLoopPolicy





#### asyncio.iscoroutine
#### asyncio.iscoroutinefunction
#### asyncio.isfuture
#### AbstractEventLoop.run_until_complete
#### AbstractEventLoop.call_soon_threadsafe
