#### Parser Content
```Java
{
Name = citrix-remote-logon
  Vendor = Citrix
  Product = Citrix XenApp
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"text":"Shadow user""", """"event":"admin-action"""", """"system":"Citrix-XenApp""""]
  Fields = [
    """"starttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)"""",
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """"username":"(({user_email}[^@"]+@[^\."]+\.[^"]+)|(({domain}[^\\"]+)\\+)?({user}[^"]+))",""",
    """({event_name}admin-action)""",
    """"text":"({additional_info}[^"]+)",""",
    """"adminaccountname":"(({account_domain}[^\\"]+)\\+)?({account_name}[^"]+)","""
  ]
}
```