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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d(\.\S+)?\s({host}[^\s]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d(\.\S+)?\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """\(({user}[^\)]{1,2000})\) CMD""",
    """\sCMD\s{1,100}\(\s{0,100}({task_name}[^\)]{1,2000}?)\s{0,100}\)""",
    """\sCMD\s{1,100}\(({task_name}[^"]{1,2000}?\s{0,100}\)\s{1,100}?\]?)\s{1,100}""",
    """\sCMD\s{1,100}({command_line}.+?)\s{0,100}("|$)"""
  ]


}
```