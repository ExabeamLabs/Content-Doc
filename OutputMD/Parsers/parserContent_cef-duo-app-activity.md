#### Parser Content
```Java
{
Name = cef-duo-app-activity
  Vendor = Duo Security
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=DUO """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) ({host}.+?) Skyformation """,
    """\WdestinationServiceName=(|({app}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:).+?))(\s+\w+=|\s*$)""",
    """"object":\s*"({object}[^"]+)""",
    """"status":\s*"({status}[^"]+)""",
    """"type":\s*"({alert_type}[^"]+)""",
    """"error":\s*"({failure_reason}[^"]+)""",
    """"email":\s*"({user_email}[^"]+)""",
    """"ip_address":\s*"({src_ip}[^"]+)""",
    """"result":\s*"({result}[^"]+)""",
    """"description":\s*"\{({additional_info}.+?)\}","""
  ]
}
```