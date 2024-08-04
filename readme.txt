mgchkj.py is an experimental script that can help find certain types of errors
in "magic pattern" files used by the "file" utility.

One implementation of "file" is at <https://darwinsys.com/file/>.

For example, here's a made-up example pattern file (call it png.magic):

0     string   \x89PNG
>4    string   \x0d\x0a\x1a\x0a
>>8   ubelong  13
>>12  string   IHDR   PNG image data

It seems to work:

$ file -m png.magic example.png
example.png: PNG image data

But mgchkj.py reports a possible error:

$ mgchkj.py png.magic
png.magic:4: Line has no effect [>>8   ubelong  13]

Given that warning, a human might be able to figure out that the last line
should begin with ">>>12", not ">>12".

Suggestions and bug reports may be made to the GitHub issue tracker, or via
email. But note that mgchkj.py is not a very serious project, and is not
expected to grow much beyond its current state. False positives and false
negatives exist, and it most cases are not considered to be bugs.

See the comments at the beginning of mgchkj.py for additional information.
