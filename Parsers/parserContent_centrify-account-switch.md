#### Parser Content
```Java
{
Name = centrify-account-switch
  Vendor = Centrify
  Product = Centrify
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite|dzdo""" , """dzdo granted"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w.\-]+)\s""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({service}.+?)\s\w+=""",
    """runas=({account}.+?)\s\w+=""",
    """EntityName=({object}.+?)\s*$""",
    """command=({process}({directory}.*?)(\/+({process_name}[^\/]+?))?)\s*(\w+=|$)"""
  ]
}
```