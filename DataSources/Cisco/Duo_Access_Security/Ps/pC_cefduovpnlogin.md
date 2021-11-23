#### Parser Content
```Java
{
Name = cef-duo-VPN-login
  Product = Duo Access Security
  DataType ="vpn-login"
  Conditions = [ """ destinationServiceName =DUO ""","""VPN""", """SUCCESS""", """"new_enrollment"""" ]

cef-duo-app-activity-2 = {
  Vendor = Cisco
  Lms = ArcSight
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Fields = [
    """"isotimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}([+-]\d\d:\d\d)?)"""",
    """\WdestinationServiceName =(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"factor":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"username":"(?!AD Sync:)({user}[^"]{1,2000})"""
    """"device":\s{0,100}"({object}[^"]{1,2000})""",
    """"object":\s{0,100}"({object}[^"]{1,2000})""",
    """"status":\s{0,100}"({status}[^"]{1,2000})""",
    """"type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"error":\s{0,100}"({failure_reason}[^"]{1,2000})""",
    """"email":\s{0,100}"({user_email}[^"]{1,2000})""",
    """"ip(_address)?":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"result":\s{0,100}"({result}[^"]{1,2000})""",
    """"description":\s{0,100}"\{({additional_info}.+?)\}",""",
    """"browser":\s{0,100}"({browser}[^"]{1,2000})""",
    """"os":\s{0,100}"({os}[^"]{1,2000})""",
    """"city":\s{0,100}"({city}[^"]{1,2000})""",
    """"state":\s{0,100}"({state}[^"]{1,2000})""",
    """"country":\s{0,100}"({country}[^"]{1,2000})""",
    """"integration":\s{0,100}"({service}[^"]{1,2000})"""",
  ]
  DupFields = ["activity->factor"
}
```