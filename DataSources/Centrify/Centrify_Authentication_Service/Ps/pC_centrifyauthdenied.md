#### Parser Content
```Java
{
Name = centrify-auth-denied
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite""", """|PAM|""" , """denied|"""]
  Fields = [
    """utc=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sahost=({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]{1,2000}?))\s{1,100}\w+=""",
    """user=({user}[^\(\)\s\$]{1,2000})"""
    """\d{1,100}\|\d{1,100}\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d{1,100})""",
    """service=({protocol}.+?)\s\w+=""",
    """reason=({failure_reason}[^=\|]{1,2000}?)(\s{1,100}\w+=|\|)"""

  ]


}
```