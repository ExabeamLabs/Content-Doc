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
    """"starttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"username":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|(({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000}))"""",
    """({event_name}admin-action)""",
    """"text":"({additional_info}[^"]{1,2000})",""",
    """"adminaccountname":"(({account_domain}[^\\"]{1,2000})\\+)?({account_name}[^"]{1,2000})","""
  ]
}
```