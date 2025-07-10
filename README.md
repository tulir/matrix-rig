# matrix-rig
Vanity room ID generator for future Matrix room versions using
[MSC4291](https://github.com/matrix-org/matrix-spec-proposals/pull/4291).

## Usage
Use `-h` to find available flags. `-u` and `-p` are the only necessary
parameters, specifying the creator user ID and the room ID prefix respectively.
`-k` can also be useful to specify the number of threads to use.

For example, the following command will use 8 threads to create a room as
`@you:example.com` whose creation event ID starts with `meow`:

```
matrix-rig -u @you:example.com -p meow -k 8
```
