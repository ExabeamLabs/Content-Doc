#### Parser Content
```Java
{
Name = cef-duo-app-activity
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=DUO """ ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"isotimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\WdestinationServiceName=(|({app}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wcat=({activity}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wduser=(({user_email}[^@\s]+@[^\s@]+)|({user}[^\s]+))""",
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:)[^@=]+?\s[^@=]+?))(\s+\w+=|\s*$)""",
    """"username"+:"+(?!AD Sync:)(({user_email}[^"\s@]+@[^"\s@]+)|({user_fullname}[^\s]+\s[^"]+)|({user}[^"]+))"""",
    """"phone":\s*"({object}[^"]+)"""",
    """"device":\s*"({object}[^"]+)""",
    """"object":\s*"(({user_email}[^"@\s]+@[^"\s@]+)|({object}[^"]+))""", 
    """"status":\s*"({status}[^"]+)""",
    """"type":\s*"({alert_type}[^"]+)""",
    """"error":\s*"({failure_reason}[^"]+)""",
    """"email":\s*"({user_email}[^"\s@]+@({email_domain}[^\s"]+))""",
    """\ssrc=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+?))(\s+\w+=|\s*$)""",
    """"ip(_address)?":\s*"(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))"""",
    """"description":\s*"\{({additional_info}[^"]+?)\}",""",
    """\Wmsg=({additional_info}[^=]+?)(\s+\w+=|\s*$)""",
    """"factor":\s*"(n\/a|({factor}[^"]+))""",
    """"reason":\s*"(User approved|Valid passcode|({failure_reason}[^"]+))"""",
    """"context":\s*"({activity}[^"]+)"""",
    """\WflexString1=(|({activity}[^=]+?))(\s+\w+=|\s*$)""",
  ]
    DupFields = ["object->device", "service->object"]
}
```