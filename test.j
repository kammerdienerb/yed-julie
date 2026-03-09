key-watcher =
    actor-spawn
        '
            while 1
                msg = (actor-receive)
                printf "key: %\n" msg

append @on-key
    '
        actor-send key-watcher ($EVENT 'key)
