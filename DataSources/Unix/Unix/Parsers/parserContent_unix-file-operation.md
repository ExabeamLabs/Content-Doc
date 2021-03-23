#### Parser Content
```Java
{
Name = unix-file-operation
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "epoch"
  Conditions = [ """ Original Address=""", """ objtype=""", """ name=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+)""",
    """Original Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """node=({host}\S+)""",
    """msg=audit\(({time}\d+)\.\d+:\d+\):""",
    """\stype=({activity_type}[^=]+?)\s*\w+=""",
    """objtype=({activity}[^=]+?)\s*\w+=""",
    """name="+({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+(\.({file_ext}[^\\\/\.;"]+))))"""
  ]
  DupFields = ["activity->action"]
}
```