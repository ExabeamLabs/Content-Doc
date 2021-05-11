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
    """({time}\w+ \d{1,100} \d\d:\d\d:\d\d)\s{0,100}:\s{0,100}({user}[^:]+?)\s{0,100}:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """; USER=({account}[^;]+?)\s{0,100};""",
    """; COMMAND=({command_line}[^;]+?)\s{0,100}(;|$|")""",
    """; COMMAND=({process}({process_directory}[^\s]+[\\\/]+)?({process_name}[^";\\\/\s]+))[\s"](?:|;|$)"""
  ]
  DupFields = [ "process_directory->directory","host->dest_host" ]
}
```