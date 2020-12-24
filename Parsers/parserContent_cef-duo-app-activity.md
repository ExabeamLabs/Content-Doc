#### Parser Content
```Java
{
Name = cef-duo-app-activity
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=DUO """ ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) .+? Skyformation """,
    """\WdestinationServiceName=(|({app}[^=]+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({activity}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wcat=({activity}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:)[^@=]+?\s[^@=]+?))(\s+\w+=|\s*$)""",
    """"username"+:"+(?!AD Sync:)(({user_email}[^"@]+@[^"@]+)|({user_fullname}[^\s]+\s[^"]+)|({user}[^"]+))"""",
    """"phone":\s*"({object}[^"]+)"""",
    """"device":\s*"({object}[^"]+)""",
    """"object":\s*"({object}[^"]+)""", 
    """"status":\s*"({status}[^"]+)""",
    """"type":\s*"({alert_type}[^"]+)""",
    """"error":\s*"({failure_reason}[^"]+)""",
    """"email":\s*"({user_email}[^@]+@({email_domain}[^"]+))""",
    """"ip(_address)?":\s*"(0\.0\.0\.0|({src_ip}[^"]+))""",
    """"result":\s*"({result}[^"]+)""",
    """"description":\s*"\{({additional_info}[^"]+?)\}",""",
    """\Wmsg=({additional_info}[^=]+?)(\s+\w+=|\s*$)""",
    """"browser":\s*"({browser}[^"]+)""",
    """"os":\s*"({os}[^"]+)""",
    """"city":\s*"({city}[^"]+)""",
    """"state":\s*"({state}[^"]+)""",
    """"country":\s*"({country}[^"]+)""",
    """"integration":\s*"({service}[^"]+)""",
    """"factor":\s*"({factor}[^"]+)""",
    """"reason":\s*"(User approved|Valid passcode|({failure_reason}[^"]+))"""",
    """"context":\s*"({activity}[^"]+)"""",
  ]
    DupFields = ["object->device", "service->object"]
}
```