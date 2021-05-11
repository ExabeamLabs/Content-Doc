#### Parser Content
```Java
{
Name = cef-duo-authentication
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=DUO """, """dproc=authentication-logs""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":({time}\d{1,100})""",
    """"isotimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"integration":\s{0,100}"({app}[^"]+)""",
    """\Wcat=({activity}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"username":"(?!AD Sync:)(({user_email}[^"\s@]+@[^"\s@]+)|({user_fullname}[^\s"]+\s[^"]+)|({user}[^"]+))"""",
    """"device":\s{0,100}"({object}[^"]+)""",
    """"email":\s{0,100}"({user_email}[^"\s@]+@({email_domain}[^\s"]+))""",
    """\ssrc=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip(_address)?":\s{0,100}"(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))"""",
    """"result":\s{0,100}"({outcome}[^"]+)""",
    """\Wmsg=({additional_info}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"browser":\s{0,100}"((?i)unknown|({browser}[^"]+))""",
    """"os":\s{0,100}"({os}[^"]+)""",
    """"city":\s{0,100}"({city}[^"]+)""",
    """"state":\s{0,100}"({state}[^"]+)""",
    """"country":\s{0,100}"({country}[^"]+)""",
    """"factor":\s{0,100}"(n\/a|({factor}[^"]+))""",
    """"reason":\s{0,100}"(({event_name}(?i)User approved|Valid passcode)|({failure_reason}[^"]+))"""",
  ]
  DupFields = ["object->device", "app->service", "factor->auth_method"]
}
```