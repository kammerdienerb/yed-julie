@on-key = (list)

macro =
    fn (&template ...)
        recursive-replace =
            fn (&self &template &args)
                foreach &elem &template
                    if ((typeof &elem) == "symbol")
                        s = (string &elem)
                        if (startswith s "$")
                            num = (parse-int (substr s 1 ((len s) - 1)))
                            if (num != nil)
                                &elem = (&args num)
                    elif ((typeof &elem) == "list")
                        &self &self &elem &args
        recursive-replace recursive-replace &template ...
        &template

reloadable-actor =
    fn (sym code)
        apply
            macro
                '
                    do
                        if (is-bound $0)
                            actor-stop $0
                            unbind $0
                        $0 := (actor-spawn (' $1))
                        $0
                sym
                code

reloadable-actor (' noisy)
    '
        while 1
            println "noisy"
            sleep 1.0

@command search-cursor-word
search-cursor-word =
    fn ()
        if ($CURSOR-WORD == nil)
            @cerr "cursor is not on a word"
        else
            @yexe "find-in-buffer" $CURSOR-WORD
            @yexe "find-prev-in-buffer"

open-buffer =
    fn (name)
        @yexe "buffer" name
