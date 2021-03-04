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
```