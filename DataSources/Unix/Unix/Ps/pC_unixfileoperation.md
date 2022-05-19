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
    """msg=audit\(({time}\d{1,100})\.\d{1,100}:\d{1,100}\):""",
    """\stype=({activity_type}[^=]{1,2000}?)\s{0,100}\w+=""",
    """objtype=({activity}[^=]{1,2000}?)\s{0,100}\w+=""",
    """name="{1,20}({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}(\.({file_ext}[^\\\/\.;"]{1,2000}))))"""
  ]
  DupFields = ["activity->action"]


}
```