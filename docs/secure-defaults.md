# Secure defaults

The default run is the safe run. Nothing below needs a flag, and none of it can be switched off.

## How the tool behaves by default

- **No network.** The tool reads the one file it is given and sends nothing anywhere. It does not download a schema, an OpenAPI document or any other page, does not follow an address from the file, does not call the API the file describes and does not check for updates. An argument that looks like an address is refused. It can run in a locked-down job with no outbound access at all.
- **No commands.** The tool never runs a program, a shell, `git` or a package manager. No name, path or value from the input is ever put on a command line.
- **No dependencies.** Node 22 or newer and nothing else, so a security check does not add a supply chain of its own. There is no `node_modules` to install before it runs.
- **Strict readers.** The JSON is read by a small reader that accepts only JSON: no comments, no trailing commas, nesting no deeper than 64 levels, a key twice in one object refused. The YAML is read by a reader for a documented subset, which refuses everything else with its line. A file that is not understood stops the run with exit code `2`; it is never read halfway and passed.
- **Reads only what is named.** The tool opens the file you name. A `$ref` that leaves the file is never opened or fetched; it is an error finding, so the gate fails until the description is one file.
- **Regular files only, bounded.** The file is opened once, its type and size are taken from the open file, and anything that is not a regular file or is over 10 MB is refused before it is read.
- **Values stay out of the report.** An example, a default, an enum value, a description text and a server address (which may carry a user name and a password) are never copied into a finding, a note or any format. A finding names the structure: the pointer, the path, the parameter or the property name, the scheme name.
- **Clean output.** Text from the input has control characters, line separators and direction controls removed and its length capped before it reaches a report or an error message, so a hostile path or name cannot rewrite the terminal or reorder what a reader sees. Markdown cells escape pipes, backslashes, line breaks and `<`, `>` and `&`. CSV cells are quoted as RFC 4180 says, and a cell that a spreadsheet would read as a formula gets a leading `'`.
- **No prototype tricks.** The input is read into objects without a prototype, so a key named `__proto__` or `constructor` is just data.
- **Loops are cut.** A `$ref` that leads back to itself is followed once and reported. A chain of references longer than 32, schemas nested deeper than 48 levels and more than 300,000 schema visits end the walk, and say so.
- **Not checked is never fine.** The two risks that a description cannot show are `not checked` in every report. A part of the description that the tool could not read is an error, not a gap that passes. A thing the tool cannot see is a review item, and the message says it cannot prove the risk.
- **The gate is on.** Without any option, an error makes the run exit with `1`. A pipeline that adds the tool notices an API key in the query string, a server at a plain http address, basic authentication over http and a `$ref` that was not followed from the first run.
- **Writes nothing to disk.** The report goes to the screen. Redirect it to a file or the job summary only when you need to keep it.

## Running it safely on a description you do not know

1. A description is data, and the tool treats it as data. Still, run it as a user with read access to the file and nothing else; it needs no account, no key and no network.
2. Read the notes and the info findings: they say what was not read (webhooks, callbacks) and what was cut, so a pass is not taken for more than it is.
3. Keep the description you check free of real secrets. The tool does not print values, but the file may travel through other tools of your pipeline.
