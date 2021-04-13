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
    """"timestamp":({time}\d+)""",
    """"isotimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"integration":\s*"({app}[^"]+)""",
    """\Wcat=({activity}[^=]+?)(\s+\w+=|\s*$)""",
    """"username":"(?!AD Sync:)(({user_email}[^"\s@]+@[^"\s@]+)|({user_fullname}[^\s"]+\s[^"]+)|({user}[^"]+))"""",
    """"device":\s*"({object}[^"]+)""",
    """"email":\s*"({user_email}[^"\s@]+@({email_domain}[^\s"]+))""",
    """\ssrc=(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+?))(\s+\w+=|\s*$)""",
    """"ip(_address)?":\s*"(0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))"""",
    """"result":\s*"({outcome}[^"]+)""",
    """\Wmsg=({additional_info}[^=]+?)(\s+\w+=|\s*$)""",
    """"browser":\s*"((?i)unknown|({browser}[^"]+))""",
    """"os":\s*"({os}[^"]+)""",
    """"city":\s*"({city}[^"]+)""",
    """"state":\s*"({state}[^"]+)""",
    """"country":\s*"({country}[^"]+)""",
    """"factor":\s*"(n\/a|({factor}[^"]+))""",
    """"reason":\s*"(({event_name}(?i)User approved|Valid passcode)|({failure_reason}[^"]+))"""",
  ]
  DupFields = ["object->device", "app->service", "factor->auth_method"]
}
```