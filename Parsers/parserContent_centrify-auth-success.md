#### Parser Content
```Java
{
Name = centrify-auth-success
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite""", """|PAM|""" , """granted|"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\sahost=({host}[^=]+?)\s+\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))(\||\s+\w+=)""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({protocol}.+?)\s\w+=""",
  ]
}

{
  Name = centrify-auth-denied
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite""", """|PAM|""" , """denied|"""]
  Fields = [
    """utc=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\sahost=({host}[^=]+?)\s+\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))\s+\w+=""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({protocol}.+?)\s\w+=""",
    """reason=({failure_reason}[^=\|]+?)(\s+\w+=|\|)"""

  ]
}

{
  Name = centrify-account-switch
  Vendor = Centrify
  Product = Centrify Zero Trust Privilege Services
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