#### Parser Content
```Java
{
Name = aix-process-created
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ CMD """, """]: (""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """\(({account}.+?)\) CMD""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """time:"({time}\d{1,100})""",
    """\sCMD \(\s{0,100}({command_line}.+?)\)""",
    """\sCMD \(\s{0,100}[^\/]{0,2000}?({process}({directory}\/.*?)({process_name}[^\/]{0,2000}?[^\\]))((\\\\)*\s|\))"""
  ]
  DupFields = [ "account->user" ]
}
```