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
    """\WdestinationServiceName=(|({app}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({activity}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(({user_email}[^@\s]+@[^\s@]+)|({user}[^\s]+))""",
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:)[^@=]+?\s[^@=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"username"{1,20}:"{1,20}(?!AD Sync:)(({user_email}[^"\s@]+@[^"\s@]+)|({user_fullname}[^\s]+\s[^"]+)|({user}[^"]+))"""",
    """"phone":\s{0,100}"({object}[^"]+)"""",
    """"device":\s{0,100}"({object}[^"]+)""",
    """"object":\s{0,100}"(({user_email}[^"@\s]+@[^"\s@]+)|({object}[^"]+))""", 
    """"status":\s{0,100}"({status}[^"]+)""",
    """"type":\s{0,100}"({alert_type}[^"]+)""",
    """"error":\s{0,100}"({failure_reason}[^"]+)""",
    """"email":\s{0,100}"({user_email}[^"\s@]+@({email_domain}[^\s"]+))""",
    """\ssrc=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip(_address)?":\s{0,100}"(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))"""",
    """"description":\s{0,100}"\{({additional_info}[^"]+?)\}",""",
    """\Wmsg=({additional_info}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"factor":\s{0,100}"(n\/a|({factor}[^"]+))""",
    """"reason":\s{0,100}"(User approved|Valid passcode|({failure_reason}[^"]+))"""",
    """"context":\s{0,100}"({activity}[^"]+)"""",
    """\WflexString1=(|({activity}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
    DupFields = ["object->device", "service->object"]
}
```