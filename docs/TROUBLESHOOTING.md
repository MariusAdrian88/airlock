# Troubleshooting

An error from a tool is one line: `error <code>: <what happened>. <next step>.`
Find the code in the tables below. A message from `airlock doctor` is in the last section.
Log files are in `%LOCALAPPDATA%\airlock\logs`. Worker problems are in `worker.log`.

## Session and role

| Code | Cause | Fix |
|---|---|---|
| `unbound` | The session has no project. | Call `projects`, then `project_open` with a name and a role. |
| `bad_role` | The role is not `dirty` or `clean`. | Use `dirty` or `clean`. |
| `role_locked` | The session has a role already. The role cannot change in a session. | Start a new session for the other role. |
| `wrong_role` | The tool is not allowed for this role or this server profile. A clean session has no code tools. | Use a dirty session, or use a spec tool. |
| `writes_disabled` | `allow_writes` is off. | Run `airlock config --set allow_writes true` and restart the client. |
| `unknown_tool` | The name is not a tool of this server. | Check the name in [TOOLS.md](TOOLS.md). |
| `not_implemented` | The tool is planned and not available yet. | Use another tool. |

## Projects and files

| Code | Cause | Fix |
|---|---|---|
| `need_name` | `project_create` got no name. | Ask the user for a project name. |
| `exists` | A project or a variable with this name exists already. | Use another name, or open the project. |
| `no_project` | The named project does not exist. | Call `projects` and use a name from the list. |
| `ambiguous_project` | Several projects exist and the call named none. | Name the project. |
| `no_binaries` | The folder has no analysable executable. | Check the path. Use `add=` with files from `program_scan`. |
| `no_binary` | The project has no binaries. | Add files with `program_add`. |
| `bad_file` | A file in `add=` or `remove=` is not in the scan. | Use file names from `program_scan`. |
| `bad_option` | The analysis option is not offered. | Use an option that `program_scan` lists. |
| `no_manifest` | The project has no manifest (file list). | Create the project again with `project_create`. |
| `no_source` | The program folder of the project is gone. | Restore the folder or move it back. |
| `unsupported` | The file is not a Windows PE file. | Give a PE executable or DLL. |
| `import_failed` | Ghidra could not import the file. The format or the language is not supported. | Check that the file is a valid PE file. See `worker.log`. |
| `outside_project` | The path is outside the program folder and `dirty\work`. | Copy the file into the program folder. |
| `not_ready` | No binary is analysed yet. | Wait. Call `index_status`. |

## Analysis state

| Code | Cause | Fix |
|---|---|---|
| `not_analysed` | The binary is queued, in analysis, or failed. The message shows the state. | Wait and call `index_status`. If it failed, read `worker.log`. |
| `ambiguous_binary` | The project has several binaries and the call named none, or the name matches several. | Name the binary with `binary=`. |
| `busy` | The worker is busy with another job. | Wait. Call `index_status`. |
| `no_program` | The binary is not in the Ghidra project, or the project switched. | Call `reindex` or `program_add`. |
| `wrong_project` | The worker works on another project. | Retry when the other work is done. |
| `project_locked` | Another process holds the Ghidra project. | Close the project in the Ghidra GUI. |

## Targets and arguments

| Code | Cause | Fix |
|---|---|---|
| `bad_args` | An argument is missing, empty or wrong. The message names it. | Correct the argument. |
| `bad_target` | The target is empty or has the wrong kind (for example an address where a name is needed). | Give a target in a form that the tool takes. |
| `not_found` | No function, feature, cluster, class or file matches. | Use `search` to find the name. |
| `ambiguous` | The name matches several items. The message lists them. | Use `binary!name`, or an address from the list. |
| `external` | The target is an imported function. It has no code. | Use `xrefs` on it to see the callers. |
| `no_function` | No function starts at the address. | Use an address inside a function. |
| `no_path` | No call chain joins the two points in the hop limit. | Raise the depth, or choose other points. |
| `not_clustered` | The function is a thunk, external, or in no cluster. | Use `function_map` to list clusters. |
| `not_supported` | The kind needs a tool that config turns off. | Turn on the set in `config.jsonc`. |
| `bad_cursor` | The cursor is unknown, expired, or from another tool. | Repeat the first call without a cursor. |
| `stale_cursor` | The function changed after the cursor was made. | Repeat the first call without a cursor. |
| `too_long` | A label or purpose text is over the limit. | Shorten the text. |
| `empty_purpose` | The purpose text is empty. | Give a text. |
| `bad_key` | The feature key has characters that are not allowed. | Use lowercase letters, digits and `- : _ .`. |
| `need_title` | A new feature needs a title. | Give `title=`. |

## Write tools

| Code | Cause | Fix |
|---|---|---|
| `bad_name` | The new name is not a valid C name. | Use letters, digits and `_`. |
| `bad_type` | Ghidra cannot parse the type text. | Correct the type. |
| `wrong_kind` | The address is a function but `kind` says another kind. | Use `kind=function`. |
| `no_variable` | The function shows no variable with this name. The message lists the names. | Use a name from the list. |
| `no_code` | No instruction at the address, or the address is not executable. | Use an address in code. |
| `uninitialized` | The address is in memory without bytes. | Use an address in initialised memory. |
| `boundary` | A patch cuts an instruction, or the new bytes do not decode to whole instructions. | Patch whole instructions. |
| `changed` | The bytes at the address differ from the expected bytes. | Read the bytes again, then retry. |

## Decompiler

| Code | Cause | Fix |
|---|---|---|
| `decompile_failed` | Ghidra or ilspycmd could not decompile the function. | Use `view=asm`. See `worker.log`. |
| `decompile_timeout` | The decompiler ran past the time limit. | Retry with `retry=true`. Raise `decompile_timeout_s` or `decompile_timeout_max_s` in config. |
| `decompiler_failed` | The decompiler could not open the program. | Call `reindex`. See `worker.log`. |
| `cancelled` | The job was cancelled. | Start the call again. |

## Frameworks and file formats

| Code | Cause | Fix |
|---|---|---|
| `not_delphi` | The binary is not a Delphi or FPC program. | Use another tool, or another binary. |
| `not_dotnet` | The binary is not a .NET assembly. | Use `binary=` with a managed file. |
| `not_qt` | The project has no Qt binary. | Use another tool. |
| `not_native` | The target has no native code (for example a .NET method). | Use `dotnet_decompile`. |
| `managed` | The function is managed code. It has no machine code. | Use `dotnet_decompile`. |
| `tool_missing` | `ilspycmd` is not set or not found. | Run `airlock doctor --fix`, or set `ilspycmd` in `config.jsonc`. |
| `dotnet_failed` | The .NET metadata cannot be read. | Check that the file is a valid assembly. |
| `resources_failed` | The PE resources cannot be read. | Check that the file is a valid PE file. |
| `not_ole` | The file is not an OLE compound file. | Use `hexdump` instead. |
| `too_big` | The OLE stream is over the size limit. | Read a smaller stream. |

## Specifications

| Code | Cause | Fix |
|---|---|---|
| `bad_topic` | The topic is not a path of lowercase segments. | Use a topic like `file-format/document/record-header`. |
| `bad_title` | The title is empty or too long. | Use a title that is 1 to the limit in characters. |
| `bad_body` | The body is empty or too long. | Use a body that is 1 to the limit in characters. |
| `bad_status` | The status is not `draft`, `reviewed` or `final`. | Use one of these. |
| `bad_format` | `spec_export` knows the format `md` only. | Use `md`. |
| `bad_source` | A source item is not in a valid form. | Use a form that the message lists. |
| `sources_required` | `spec_write` needs sources. | Add `sources`. |
| `spec_has_code` | The text has a code block or code. Specifications may not carry code. | Describe the behaviour in prose and tables. |
| `spec_has_address` | The text has an address. | Name the thing by its role. |
| `spec_has_bytes` | The text has a long run of hex bytes. | Describe the layout as fields. |
| `spec_has_ghidra_names` | The text has a Ghidra name such as `FUN_...`. | Use the role in prose. |

## Worker and Ghidra

| Code | Cause | Fix |
|---|---|---|
| `not_configured` | `ghidra_dir` is not set. | Run `airlock init --ghidra <folder>`. |
| `pyghidra_missing` | PyGhidra is not installed in the Python of airlock. | Run `airlock doctor --fix`. |
| `ghidra_start_failed` | PyGhidra or the JVM stopped during start. | Run `airlock doctor --start`. Check `jdk_dir`. See `worker.log`. |
| `ghidra_not_started` | A call came before Ghidra started. | Retry the call. |
| `ghidra_error` | Ghidra raised an exception. | See `worker.log`. |
| `version_mismatch` | The project came from another Ghidra version. | Create the project again. |
| `out_of_memory` | The JVM has too little memory. | Raise `jvm_max_memory` in config and restart. |
| `timeout` | The worker did not answer in time. The server restarted it. | Retry the call. |
| `worker_exited` | The worker process stopped. | Retry the call. See `worker.log`. |
| `io_error` | Ghidra could not read or write a file. | Check the disk and the folder rights. |

## Messages of `airlock doctor`

Each line starts with `[OK   ]`, `[WARN ]`, `[FAIL ]` or `[FIXED]`.

| Message | Fix |
|---|---|
| `python`: the version is not 3.9 to 3.13 | Use Python 3.13. |
| `config`: no config file | Run `airlock init --ghidra <folder>`. |
| `config`: the file is old | Run `airlock doctor --fix`, or `airlock config upgrade`. |
| `data dir` or `projects root` on a network drive | Use a local disk. Change `index_dir` or `projects_root`. |
| `ghidra`: `ghidra_dir` is not set, or the folder is not Ghidra | Run `airlock init --ghidra <folder>`. |
| `ghidra/python`, `jpype bundle`: Ghidra has no wheel for this Python | Use Python 3.13. |
| `jdk`: Java is missing or too old | Install JDK 21 or newer. Set `jdk_dir` in `config.jsonc`. |
| `pyghidra`: not installed or a wrong version | Run `airlock doctor --fix`. |
| `ilspycmd`: not found or too old | Run `airlock doctor --fix`. Only .NET decompile needs it. |
| `idr_kb_dir`, `delphi sigdb`, `warp_dir`: no files | Optional. Only Delphi naming needs them. |
| `ghidra start`: the worker or Ghidra did not start | Read the code in the message and use its row above. |
