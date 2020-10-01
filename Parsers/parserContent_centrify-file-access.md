#### Parser Content
```Java
{
Name = centrify-file-access
  Vendor = Centrify
  Product = Centrify Audit and Monitoring Service
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite|""" , """|SFTP"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({protocol}.+?)\s\w+=""",
    """operation=({activity}.+?)\s\w+=""",
    """arguments=({file_path}({file_parent}.*?)(\/+({file_name}[^\/]+?))?)\s*(\w+=|$)""",
    """reason=({failure_reason}.+?)\s*$"""
  ]
}
```