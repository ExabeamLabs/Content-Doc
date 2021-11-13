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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """\w{3}\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """\(({account}[^\)]{1,2000}?)\) CMD""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """time:"({time}\d{1,100})""",
    """\sCMD \(\s{0,100}({command_line}.+?)\s{0,100}\)""",
    """\sCMD \(\s{0,100}[^\/]{0,2000}?({process}({directory}\/[^\)]{0,2000}?)({process_name}[^\/\s]{0,2000}?[^\\\/])?)((\\\\)*\s|\))"""
  ]
  DupFields = [ "account->user" ]


}
```