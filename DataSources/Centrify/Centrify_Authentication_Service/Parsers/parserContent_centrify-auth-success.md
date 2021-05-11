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
    """utc=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\sahost=({host}[^=]+?)\s{1,100}\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))(\||\s{1,100}\w+=)""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d{1,100}\|\d{1,100}\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d{1,100})""",
    """service=({protocol}.+?)\s\w+=""",
  ]
}
```