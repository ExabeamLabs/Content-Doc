#### Parser Content
```Java
{
Name = s-process-created-carbonblack
  Vendor = VMware
  Product = App Control
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """process_guid""", """ingress.event.procstart""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\Wtimestamp(":|=)({time}\d{10})""",
    """\Wtype(":"|=)({activity_type}[^"]{1,2000}?)\s{0,100}("|\w+=|$)""",
    """\Wusername(":"|=)(({domain}[^\\]{1,2000})\\+)?({user}[^"\s]{1,2000})""",
    """\Wcomputer_name(":"|=)({dest_host}[\w\-.]{1,2000})""",
    """\Wsensor_id(":|=)({sensor_id}\d{1,100})""",
    """\Wmd5(":"|=)({md5}[^"]{1,2000}?)\s{0,100}("|\w+=|$)""",
    """\Wpath(":"|=)({path}[^"]{1,2000}?)\s{0,100}("|\w+=|$)""",
    """\Wparent_path(":"|=)({parent_path}[^"]{1,2000}?)\s{0,100}("|\w+=|$)""",
    """\Wcommand_line(":"|="?)(?:|({command_line}.+?))\s{0,100}("|\w+=|$)""",
    """\Wpid(":|=)({pid}\d{1,100})""",
    """\Wprocess_guid(":"|=)({process_guid}[^"]{1,2000}?)\s{0,100}("|\w+=|$)""",
    """\Wparent_process_guid(":"|=)({parent_process_guid}[^"]{1,2000}?)\s{0,100}("|\w+=|$)""",
    """\Wpath(":"|=)({process}({directory}(?:[^"]{1,2000}?)?[\\\/])?({process_name}[^\\\/"]{1,2000}?))\s{0,100}("|\w+=|$)""",
    """\Wparent_path(":"|=)({parent_process}({parent_process_directory}(?:[^"]{1,2000}?)?[\\\/])?({parent_process_name}[^\\\/"]{1,2000}?))\s{0,100}("|\w+=|$)""",
    """\Wcommand_line(":"|="?)(\\"{0,20})?(\w+|((([^"]{1,2000})?[\\\/])?([^\\\/"\s]{1,2000})))(?:[^\s]{0,2000})?\s{0,100}\/({arg}[^\s"]{1,2000})""",
  ]
  DupFields = [ "directory->process_directory" ]


}
```