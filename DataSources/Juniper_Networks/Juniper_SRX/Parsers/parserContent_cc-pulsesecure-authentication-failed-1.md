#### Parser Content
```Java
{
Name = cc-pulsesecure-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Active Directory authentication server""", """Domain trust check failed.""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """({additional_info}Active Directory authentication server \'({auth_server}[^\']{1,2000})\': ({failure_reason}Domain trust check failed). Administrator may need to rejoin to the domain.)"""
  ]
}
cef-pulsesecure-vpn-events = {
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"host":"({host}[^"]{1,2000})"""",
    """"timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(?:Default Network|Root)::(({domain}[^\\\(]{1,2000})\\)?(System|({user}[^\(]{1,2000}))\(({realm}[^\)]{1,2000})?\)\[({resource}[^\]]{1,2000})?\]""",
    """\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})"""
  ]

```