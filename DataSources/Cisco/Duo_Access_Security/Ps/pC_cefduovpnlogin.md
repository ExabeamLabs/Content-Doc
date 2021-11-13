#### Parser Content
```Java
{
Name = cef-duo-VPN-login
  Product = Duo Access Security
  DataType ="vpn-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName =DUO ""","""VPN""", """SUCCESS""" ]

cef-duo-app-activity-2 = {
  Vendor = Cisco
  Lms = ArcSight
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) .+? Skyformation """,
    """\WdestinationServiceName =(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({activity}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"username":"(?!AD Sync:)({user}[^"]{1,2000})"""
    """\Wsuser=(|anonymous|({user_fullname}(?!AD Sync:)[^@=]{1,2000}?\s[^@=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"device":\s{0,100}"({object}[^"]{1,2000})""",
    """"object":\s{0,100}"({object}[^"]{1,2000})""",
    """"status":\s{0,100}"({status}[^"]{1,2000})""",
    """"type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"error":\s{0,100}"({failure_reason}[^"]{1,2000})""",
    """"email":\s{0,100}"({user_email}[^"]{1,2000})""",
    """"ip(_address)?":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"result":\s{0,100}"({result}[^"]{1,2000})""",
    """"description":\s{0,100}"\{({additional_info}.+?)\}",""",
    """\Wmsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"browser":\s{0,100}"({browser}[^"]{1,2000})""",
    """"os":\s{0,100}"({os}[^"]{1,2000})""",
    """"city":\s{0,100}"({city}[^"]{1,2000})""",
    """"state":\s{0,100}"({state}[^"]{1,2000})""",
    """"country":\s{0,100}"({country}[^"]{1,2000})""",
	"""\sext_integration=({service}.*?)(\s\w+=|\s{0,100}$)""",
    """ext_factor=({factor}.*?)(\s\w+=|\s{0,100}$)"""
  
}
```