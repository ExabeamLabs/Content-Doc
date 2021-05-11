#### Parser Content
```Java
{
Name = centrify-account-switch
  Vendor = Centrify
  Product = Centrify Zero Trust Privilege Services
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "epoch"
  Conditions = ["""Centrify Suite|dzdo""" , """dzdo granted"""]
  Fields = [
    """utc=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w.\-]+)\s""",
    """user=({user}[^\(\)\s\$]+)"""
    """\d{1,100}\|\d{1,100}\|({event_name}.+?)\|\d""",
    """status=({outcome}.+?)\s\w+=""",
    """pid=({process_id}\d{1,100})""",
    """service=({service}.+?)\s\w+=""",
    """runas=({account}.+?)\s\w+=""",
    """EntityName=({object}.+?)\s{0,100}$""",
    """command=({process}({directory}.*?)(\/+({process_name}[^\/]+?))?)\s{0,100}(\w+=|$)"""
  ]
}
```