#### Parser Content
```Java
{
Name = centrify-process
  Vendor = Centrify
  Product = Centrify Infrastructure Services
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = ["""AUDIT_TRAIL|Centrify Suite""" , """dzdo command execution ends"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """pid=({process_id}\d+)""",
    """command=({process}({directory}.*?)(\/+({process_name}[^\/]+?))?)\s*(\w+=|$)"""
    """user=({user}[^\(\)\s\$]+)"""
    """status=({outcome}.+?)\s\w+=""",
    """parameters=({command_line}.+?)$"""
  ]
}
```