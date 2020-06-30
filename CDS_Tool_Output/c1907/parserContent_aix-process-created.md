#### Parser Content
```Java
{
Name = aix-process-created
  Vendor = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ CMD """, """]: (""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
    """\(({account}.+?)\) CMD""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """time:"({time}\d+)""",
    """\sCMD \(\s*({command_line}.+?)\)""",
    """\sCMD \(\s*[^\/]*?({process}({directory}\/.*?)({process_name}[^\/]*?[^\\]))((\\\\)*\s|\))"""
  ]
  DupFields = [ "account->user" ]
}
```