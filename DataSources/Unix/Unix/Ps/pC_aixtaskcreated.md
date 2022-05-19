#### Parser Content
```Java
{
Name = aix-task-created
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "task-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ CMD """, """]: (""", """ CROND[""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """\(({user}[^\)]{1,2000})\) CMD""",
    """\sCMD\s{1,100}\(({task_name}[^\s\)]{1,2000})""",
    """\sCMD \(\s{0,100}({command_line}[^\)]{1,2000})\s{0,100}\)""",
  ]


}
```