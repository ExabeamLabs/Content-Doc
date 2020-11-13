#### Parser Content
```Java
{
Name = s-process-created-carbonblack
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """process_guid""", """ingress.event.procstart""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\Wtimestamp(":|=)({time}\d{10})""",
    """\Wtype(":"|=)({activity_type}[^"]+?)\s*("|\w+=|$)""",
    """\Wusername(":"|=)(({domain}[^\\]+)\\+)?({user}[^"\s]+)""",
    """\Wcomputer_name(":"|=)({dest_host}[\w\-.]+)""",
    """\Wsensor_id(":|=)({sensor_id}\d+)""",
    """\Wmd5(":"|=)({md5}[^"]+?)\s*("|\w+=|$)""",
    """\Wpath(":"|=)({path}[^"]+?)\s*("|\w+=|$)""",
    """\Wparent_path(":"|=)({parent_path}[^"]+?)\s*("|\w+=|$)""",
    """\Wcommand_line(":"|="?)(?:|({command_line}.+?))\s*("|\w+=|$)""",
    """\Wpid(":|=)({pid}\d+)""",
    """\Wprocess_guid(":"|=)({process_guid}[^"]+?)\s*("|\w+=|$)""",
    """\Wparent_process_guid(":"|=)({parent_process_guid}[^"]+?)\s*("|\w+=|$)""",
    """\Wpath(":"|=)({process}({directory}(?:[^"]+?)?[\\\/])?({process_name}[^\\\/"]+?))\s*("|\w+=|$)""",
    """\Wparent_path(":"|=)({parent_process}({parent_process_directory}(?:[^"]+?)?[\\\/])?({parent_process_name}[^\\\/"]+?))\s*("|\w+=|$)""",
    """\Wcommand_line(":"|="?)(\\"*)?(\w+|((([^"]+)?[\\\/])?([^\\\/"\s]+)))(?:[^\s]*)?\s*\/({arg}[^\s"]+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```