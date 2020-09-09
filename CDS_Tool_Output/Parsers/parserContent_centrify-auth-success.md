#### Parser Content
```Java
{
Name = centrify-auth-success
  Vendor = Centrify
  Product = Centrify
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite""", """|PAM|""" , """granted|"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({protocol}.+?)\s\w+=""",
  ]
}

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

{
  Name = centrify-file-access
  Vendor = Centrify
  Product = Centrify
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