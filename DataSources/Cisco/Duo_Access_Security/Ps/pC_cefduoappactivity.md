#### Parser Content
```Java
{
Name = cef-duo-app-activity
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName =DUO """ ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"isotimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\WdestinationServiceName =(|({app}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({activity}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})|({user}[^\s]{1,2000}))""",
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:)[^@=]{1,2000}?\s[^@=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"username"{1,20}:"{1,20}(?!AD Sync:)(({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})|({user_fullname}[^\s]{1,2000}\s[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"phone":\s{0,100}"({object}[^"]{1,2000})"""",
    """"device":\s{0,100}"({object}[^"]{1,2000})""",
    """"object":\s{0,100}"(({user_email}[^"@\s]{1,2000}@[^"\s@]{1,2000})|({object}[^"]{1,2000}))""", 
    """"status":\s{0,100}"({status}[^"]{1,2000})""",
    """"type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"error":\s{0,100}"({failure_reason}[^"]{1,2000})""",
    """"email":\s{0,100}"({user_email}[^"\s@]{1,2000}@({email_domain}[^\s"]{1,2000}))""",
    """\ssrc=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip(_address)?":\s{0,100}"(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]{1,2000}))"""",
    """"description":\s{0,100}"\{({additional_info}[^"]{1,2000}?)\}",""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"factor":\s{0,100}"(n\/a|({factor}[^"]{1,2000}))""",
    """"reason":\s{0,100}"(User approved|Valid passcode|({failure_reason}[^"]{1,2000}))"""",
    """"context":\s{0,100}"({activity}[^"]{1,2000})"""",
    """\WflexString1=(|({activity}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
    DupFields = ["object->device", "service->object"]


}
```