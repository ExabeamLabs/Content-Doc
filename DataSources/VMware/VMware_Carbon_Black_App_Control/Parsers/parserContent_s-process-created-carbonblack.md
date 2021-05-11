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
    """\Wtype(":"|=)({activity_type}[^"]+?)\s{0,100}("|\w+=|$)""",
    """\Wusername(":"|=)(({domain}[^\\]+)\\+)?({user}[^"\s]+)""",
    """\Wcomputer_name(":"|=)({dest_host}[\w\-.]+)""",
    """\Wsensor_id(":|=)({sensor_id}\d{1,100})""",
    """\Wmd5(":"|=)({md5}[^"]+?)\s{0,100}("|\w+=|$)""",
    """\Wpath(":"|=)({path}[^"]+?)\s{0,100}("|\w+=|$)""",
    """\Wparent_path(":"|=)({parent_path}[^"]+?)\s{0,100}("|\w+=|$)""",
    """\Wcommand_line(":"|="?)(?:|({command_line}.+?))\s{0,100}("|\w+=|$)""",
    """\Wpid(":|=)({pid}\d{1,100})""",
    """\Wprocess_guid(":"|=)({process_guid}[^"]+?)\s{0,100}("|\w+=|$)""",
    """\Wparent_process_guid(":"|=)({parent_process_guid}[^"]+?)\s{0,100}("|\w+=|$)""",
    """\Wpath(":"|=)({process}({directory}(?:[^"]+?)?[\\\/])?({process_name}[^\\\/"]+?))\s{0,100}("|\w+=|$)""",
    """\Wparent_path(":"|=)({parent_process}({parent_process_directory}(?:[^"]+?)?[\\\/])?({parent_process_name}[^\\\/"]+?))\s{0,100}("|\w+=|$)""",
    """\Wcommand_line(":"|="?)(\\"{0,20})?(\w+|((([^"]+)?[\\\/])?([^\\\/"\s]+)))(?:[^\s]*)?\s{0,100}\/({arg}[^\s"]+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```