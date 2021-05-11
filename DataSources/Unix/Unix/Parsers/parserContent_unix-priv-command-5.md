#### Parser Content
```Java
{
Name = unix-priv-command-5
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """The privilege command""", """is executed by"""]
  Fields = [
    """exabeam_host=(::ffff:)?({host}[\w.\-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Message forwarded from (::ffff:)?({host}[^\s:]+)""",
    """The privilege command ({command_line}({process}({directory}.+?)({process_name}[^\/]+?))), is executed"""
    """executed by user with id ({user_id}\d{1,100})"""
  ]
  DupFields = ["directory->process_directory"]
}
```