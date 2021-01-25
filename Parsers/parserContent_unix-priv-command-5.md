#### Parser Content
```Java
{
Name = unix-priv-command-5
  Vendor = Unix
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """The privilege command""", """is executed by"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Message forwarded from ({host}[^\s:]+)""",
    """The privilege command ({command_line}({process}({directory}.+?)({process_name}[^\/]+?))), is executed"""
    """executed by user with id ({user_id}\d+)"""
  ]
  DupFields = ["directory->process_directory"]
}
```