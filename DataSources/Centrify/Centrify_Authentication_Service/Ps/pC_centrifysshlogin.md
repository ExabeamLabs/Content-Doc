#### Parser Content
```Java
{
Name = centrify-ssh-login
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite|Centrify""" , """SSHD granted"""]
  Fields = [
    """utc=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sahost=({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sclient=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]{1,2000}?))\s{1,100}\w+=""",
    """user=({user}[^\(\)\s\$]{1,2000})"""
    """\d{1,100}\|\d{1,100}\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d{1,100})""",
    """service=({process}.+?)\s\w+=""",
    """EntityName =(.+\\+)?({dest_host}[^"\s]{1,2000})(\s|$)"""
  ]


}
```