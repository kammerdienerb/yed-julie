exists-in-PATH =
    fn (name)
        PATH  = (getenv "PATH")
        paths = (select (PATH == nil) (list) (split PATH ":"))
        any (lambda (path) (fexists (fmt "%/%" path name))) paths

if (exists-in-PATH "rg")
    @set-var
