#### Parser Content
```Java
{
Name = aix-task-created-1
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "task-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """) CMD (""", """ CRON[""", """]: (""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)""",
    """\(({user}[^\)]+)\) CMD""",
    """\sCMD\s{1,100}\(({task_name}[^\s\)]+)""",
    """\sCMD \(\s{0,100}({command_line}[^\)]+)\)""",
  ]
}
```