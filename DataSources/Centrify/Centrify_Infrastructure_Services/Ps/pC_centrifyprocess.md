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
    """utc=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\d{1,100}\|\d{1,100}\|({event_name}.+?)\|\d""",
    """pid=({process_id}\d{1,100})""",
    """command=({process}({directory}.*?)(\/+({process_name}[^\/]{1,2000}?))?)\s{0,100}(\w+=|$)"""
    """user=({user}[^\(\)\s\$]{1,2000})"""
    """status=({outcome}.+?)\s\w+=""",
    """parameters=({command_line}.+?)$"""
  ]


}
```