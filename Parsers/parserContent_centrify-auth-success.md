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
    """\sahost=({host}[^=]+?)\s+\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))(\||\s+\w+=)""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d+\|\d+\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d+)""",
    """service=({protocol}.+?)\s\w+=""",
  ]
}
```