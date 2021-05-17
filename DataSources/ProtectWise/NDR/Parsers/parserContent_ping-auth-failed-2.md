#### Parser Content
```Java
{
Name = ping-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """|OAuth|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s{0,100}(AUTHN_ATTEMPT|OAuth|SSO)\s{0,100}\|)\s{0,100}([^\|]{0,2000}\|){9}\s{0,100}(|({failure_reason}[^\|]{0,2000}?))\s{0,100}\|""",
  ]
}
ping-events = {
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Splunk
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Fields = [
    """"Time":\s{0,100}"{0,20}({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """"duid":\s{0,100}"(({domain}[^"@\\\/]{1,2000})[\\\/]{1,2000})?({user}[^@"\\\/]{1,2000})"""",
    """"duid":\s{0,100}"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})""""
    """"SRCIP":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"remoteAddr":\s{0,100}"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"Status":\s{0,100}"({outcome}[^"]{1,2000})""",
    """"Protocol":\s{0,100}"({protocol}[^"]{1,2000})""",
    """"PingHost":\s{0,100}"({host}[^"]{1,2000})""",
    """"EventType":\s{0,100}"({activity}[^"]{1,2000})""",
    """"DescriptionFail":\s{0,100}"({failure_reason}[^"]{1,2000})""",
  ]

```