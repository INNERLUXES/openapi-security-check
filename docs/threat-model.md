# Threat model

## What the tool touches

- It reads the one file named on the command line. Nothing else on the disk is opened.
- It does not follow a path or an address written inside the file. A symbolic link given as the argument is followed, because the person who runs the tool named it; the target must be a regular file.
- It writes only to the screen (standard output and standard error).
- It opens no network connection and runs no program: not a shell, not `git`, not a validator, not the API.

## What the input may hold

A description is often checked in a pipeline that runs on pull requests, including pull requests from people outside the team, and a description may come from a partner or a vendor. The tool treats the file as possibly hostile. It can be huge, very deeply nested, or hold very many values. It can hold a schema that contains itself, a chain of references that never ends, or thousands of schemas that refer to one another. A key can be named `__proto__` or `constructor`. A path, a name or a server address can be very long or hold control and direction characters. A server address can hold a user name and a password. A `$ref` can name a file or an address. An example can hold anything.

## What could go wrong, and what stops it

| Risk | Control |
| --- | --- |
| A huge file, deeply nested JSON or YAML, or very many values exhaust memory or time | A file over 10 MB is refused from the size of the open file before it is read; JSON deeper than 64 levels, or with more than 200,000 values, is refused; YAML has limits on depth, lines and line length; more than 5,000 operations is refused. The readers recurse only as deep as their limits |
| A schema that contains itself, or a chain of `$ref`, makes the walk run for ever or overflow the stack | A chain of references longer than 32 counts as a cycle; a schema that is reached again while it is being walked is checked once and reported (`ref-cycle`); schemas deeper than 48 levels or more than 300,000 visits end the walk (`limit-reached`); a schema reached twice for the same purpose is walked once. The search for references uses a list, not recursion |
| A crafted path, name or server address makes a pattern run for a very long time | Text is cut to a fixed length before a pattern runs on it; the patterns are anchored and have bounded repeats and no nested repetition. Tests run very long near misses, runs of braces and long addresses and check the time |
| A `$ref` makes the tool fetch or open another file | The tool has no code that opens a connection or a second file; a `$ref` that does not start with `#/` is reported by place and never opened. A test checks that no module imports a network or process module |
| A key named `__proto__` or `constructor` changes how objects behave | The description is read into objects without a prototype, and a pointer step follows own properties only. A test checks that no prototype changes |
| A path or a name rewrites the terminal through escape sequences, or reorders text with direction characters | Control characters (C0 and C1), line and paragraph separators and Unicode direction controls are replaced by a space before any text reaches a report or an error message, and the length is capped |
| A value breaks the Markdown table in the job summary, or hides text as an HTML tag | Pipes, backslashes, line breaks, `<`, `>` and `&` are escaped in every table cell |
| A CSV report runs a formula when opened in a spreadsheet | Cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading `'`; every cell is quoted as RFC 4180 says |
| A secret in the description (an example value, a default, a user name and a password in a server address) is copied into a report, a job log or the job summary | No value of the description is copied into a finding; only structure is named. The address of a server and of a `$ref` is never printed. Tests put marker values in examples, defaults, enums, descriptions and a server address and check that they appear in no report |
| A part of the description is skipped, and a check passes without having run | A remote or an unresolved `$ref` is an error, a cut walk is an error, a description that cannot be read stops the run with exit code `2`, and the two risks that a description cannot show are `not checked`. Nothing is guessed |
| The argument names a URL, so the tool becomes a fetcher | Arguments that look like addresses are refused; reading from standard input is refused |
| A pipe or a device in place of the file makes the tool hang | The type is looked at before the file is opened and again on the open file, and anything that is not a regular file is refused |

## Out of scope

What the API does at run time, the server that serves it, the secrets that its operations use, and the correctness of the OWASP pages and the specifications the tool follows. [limits.md](limits.md) lists what a check of a description cannot see.
