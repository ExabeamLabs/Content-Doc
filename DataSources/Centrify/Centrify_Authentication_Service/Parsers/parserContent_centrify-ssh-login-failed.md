#### Parser Content
```Java
{
Name = centrify-ssh-login-failed
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite|Centrify""" , """SSHD denied"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\sahost=({host}[^=]+?)\s+\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))\s+\w+=""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({process}.+?)\s\w+=""",
    """EntityName=(.+\\+)?({dest_host}[^"\s]+)(\s|$)"""
    """reason=({failure_reason}[^=\|]+?)(\s+\w+=|\|)"""
  ]
}
```