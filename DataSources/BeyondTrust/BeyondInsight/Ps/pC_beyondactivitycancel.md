#### Parser Content
```Java
{
Name = beyond-activity-cancel
  DataType = "app-activity"
  Conditions = [ """"operation":"Cancel"""", """"vendor":"BeyondTrust"""", """"product":"BeyondInsight"""", """"eventdesc":""" ]

json-beyondtrust-activity = {
  Vendor = BeyondTrust
  Product = BeyondInsight
  Lms = Direct
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """"eventdate":"({time}\w\w\w\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """"sourcehost":"({host}[\w\-\.]{1,2000})""",
    """"sourceip":"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """"user":"(({domain}[^\\\/]{1,2000})\\+)?(Internal process|({user}[^"]{1,2000}))""",
    """"operation":"({activity}[^"]{1,2000})""",
    """"failed":"({outcome}\d)""",
    """"ipaddress":"({dest_ip}[A-Fa-f:\d\.]{1,2000})""",
    """"target":"Asset:({dest_host}[\w\-\.]{1,200})\sMAccount:({account}[\w\-\.]{1,2000})""",
    """"target":"Domain:[^:]{1,200}?MAccount:({account}[\w\-\.]{1,2000})""",
    """"target":"[^"]{1,200}?ManagedAccount=({account}[\w\-\.]{1,2000})""",
    """"target":"[^\/,]{1,2000}\/({dest_host}[\w\-\.]{1,2000}),\sAccount\s""",
    """({app}BeyondInsight)"""
    ]
 
}
```