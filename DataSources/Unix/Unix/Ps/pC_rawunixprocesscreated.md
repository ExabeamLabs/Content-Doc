#### Parser Content
```Java
{
Name = raw-unix-process-created
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """; USER=""", """; COMMAND=""" ]
  Fields = [
    """({time}\w+ \d{1,100} \d\d:\d\d:\d\d)\s{0,100}:\s{0,100}({user}[^:]{1,2000}?)\s{0,100}:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(gcs-topic|({host}\S+))""",
    """"agent_hostname":"({host}[^"]{1,200})"""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """; USER=({account}[^;]{1,2000}?)\s{0,100};""",
    """; COMMAND=({command_line}[^;]{1,2000}?)\s{0,100}(;|$|")""",
    """; COMMAND=({process}({process_directory}[^\s]{1,2000}[\\\/]{1,2000})?({process_name}[^";\\\/\s]{1,2000}))[\s"](?:|;|$)"""
  ]
  DupFields = [ "process_directory->directory","host->dest_host" ]


}
```