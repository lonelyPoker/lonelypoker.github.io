```javascript
function background_task() {
    return new Promise(async function (resolve, reject) {
        if (Math.random()) {
            for (let index = 0; index < 10; index++) {
                await async_sleep(4)
                console.log("支线任务。。。")
            }
            resolve("success");
        } else {
            reject("failed");
        }
    })
}
function async_sleep(time) {
    return new Promise((resolve, reject) => {
        try {
            setTimeout(() => {
                resolve(undefined);
            }, parseInt(time) * 1000);
        } catch (error) {
            reject(error.message);
        }
    })
}
async function main(){
    background_task().then(x=>console.log(x));
    await async_sleep(4);
    console.log(1000);
}
function interval_task_invoke(func,time){
    return new Promise(function(resolve,reject){
        try{
            let interval_task_id = setInterval(func,parseInt(time) * 1000);
            resolve(interval_task_id)
        }catch{
            reject(new Error("create interval task error."));
        }
    })
}

async function main(){
    let task_id = await interval_task_invoke(function(){
        1 / 0
    },1)
    console.log(task_id);
    await async_sleep(10);
    clearInterval(task_id)
}

main()
```