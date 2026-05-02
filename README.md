# Detect `AF_ALG` sockets
Recently the https://copy.fail exploit was released, it uses `AF_ALG` (aead) to achieve arbitrary page write. 
If you're looking for a way to determine whether its safe to just turn off the `AF_ALG` kernel module entirely this tool will give you a list of processes that currently use `AF_ALG` that may need to be migrated before doing so. 


## Running

```sh
sudo go run main.go
# Or
go build
sudo ./detect-running-alg-socket
# Or 
curl ...
```


## Arguments

```sh
Usage of ./detect-running-alg-socket:
  -ignore-permissions-errors
        ignore permission errors
  -stream
        enable streaming mode
```

Streaming mode will return the list of processes and their file descriptors that use `AF_ALG` while the scan is funning. 

## Output format

Just a simple json blob.

For example (without `-stream`)
```js
{
    "alg_sockets": [
        {
            "pid": 1492,
            "fd": 15,
            "comm": "bluetoothd"
        },
        {
            "pid": 1492,
            "fd": 17,
            "comm": "bluetoothd"
        },
        {
            "pid": 5355,
            "fd": 3,
            "comm": "test"
        }
    ]
}
```

Example of an error:

```js
{
    "pid": 999,
    "fd": -1,
    "comm": "kworker/R-btrfs-cache",
    "error": "unable to read pid 999 file descriptors, potentially try root: open /proc/999/fd: permission denied"
}
```
