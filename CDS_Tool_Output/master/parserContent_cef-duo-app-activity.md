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
    """\Wcat=({activity}.+?)(\s+\w+=|\s*$)""",
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:)[^@=]+?\s[^@=]+?))(\s+\w+=|\s*$)""",
    """"username":"(?!AD Sync:)({user}[^"]+)""",
    """"phone":\s*"({object}[^"]+)"""",
    """"device":\s*"({object}[^"]+)""",
    """"object":\s*"({object}[^"]+)""", 
    """"status":\s*"({status}[^"]+)""",
    """"type":\s*"({alert_type}[^"]+)""",
    """"error":\s*"({failure_reason}[^"]+)""",
    """"email":\s*"({user_email}[^"]+)""",
    """"ip(_address)?":\s*"({src_ip}[^"]+)""",
    """"result":\s*"({result}[^"]+)""",
    """"description":\s*"\{({additional_info}.+?)\}",""",
    """\Wmsg=({additional_info}.+?)(\s+\w+=|\s*$)""",
    """"browser":\s*"({browser}[^"]+)""",
    """"os":\s*"({os}[^"]+)""",
    """"city":\s*"({city}[^"]+)""",
    """"state":\s*"({state}[^"]+)""",
    """"country":\s*"({country}[^"]+)""",
    """\sext_integration=({service}.*?)(\s\w+=|\s*$)""",
    """ext_factor=(n/a|({factor}.*?))(\s\w+=|\s*$)""",
    """"reason":\s*"(User approved|Valid passcode|({failure_reason}[^"]+))"""",
    """"context":\s*"({activity}[^"]+)"""",
  ]
    DupFields = ["object->device"]
}
```