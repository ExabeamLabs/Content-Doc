#### Parser Content
```Java
{
Name = cef-duo-authentication
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ destinationServiceName =DUO """, """dproc=authentication-logs""", """"new_enrollment"""" ]
  Fields = [
    """exabeam_host=(cc|({host}[^\s]{1,2000}))""",
    """"timestamp":({time}\d{1,100})""",
    """"isotimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}([+-]\d\d:\d\d)?)"""",
    """"integration":\s{0,100}"({app}[^"]{1,2000})""",
    """"factor":\s{0,100}"(?:(n\/a)|({activity}[^"]{1,2000}))"""",
    """"username":"(?!AD Sync:)(({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})|({user_fullname}[^\s"]{1,2000}\s[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"device":\s{0,100}"({object}[^"]{1,2000})""",
    """"email":\s{0,100}"({user_email}[^"\s@]{1,2000}@({email_domain}[^\s"]{1,2000}))""",
    """"ip(_address)?":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"result":\s{0,100}"({outcome}[^"]{1,2000})""",
    """"browser":\s{0,100}"((?i)unknown|({browser}[^"]{1,2000}))""",
    """"os":\s{0,100}"({os}[^"]{1,2000})""",
    """"city":\s{0,100}"({city}[^"]{1,2000})""",
    """"state":\s{0,100}"({state}[^"]{1,2000})""",
    """"country":\s{0,100}"({country}[^"]{1,2000})""",
    """"reason":\s{0,100}"(({event_name}(?i)User approved|Valid passcode|Remembered device|Trusted network)|({failure_reason}[^"]{1,2000}))"""",
  ]
  DupFields = ["object->device", "app->service", "activity->factor"]


}
```