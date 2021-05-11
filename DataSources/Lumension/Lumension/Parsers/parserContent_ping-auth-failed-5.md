#### Parser Content
```Java
{
Name = ping-auth-failed-5
  DataType = "authentication-failed"
  Conditions = [ """| OAuth|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s{0,100}(AUTHN_ATTEMPT|OAuth|SSO)\s{0,100}\|)\s{0,100}([^\|]*\|){9}\s{0,100}(|({failure_reason}[^\|]*?))\s{0,100}\|""",
  ]
}
ping-events = {
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Splunk
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Fields = [
    """"Time":\s{0,100}"{0,20}({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """"duid":\s{0,100}"(({domain}[^"@\\\/]+)[\\\/]+)?({user}[^@"\\\/]+)"""",
    """"duid":\s{0,100}"({user_email}[^"\s@]+@[^"\s@]+)""""
    """"SRCIP":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """"remoteAddr":\s{0,100}"({dest_ip}[a-fA-F\d.:]+)""",
    """"Status":\s{0,100}"({outcome}[^"]+)""",
    """"Protocol":\s{0,100}"({protocol}[^"]+)""",
    """"PingHost":\s{0,100}"({host}[^"]+)""",
    """"EventType":\s{0,100}"({activity}[^"]+)""",
    """"DescriptionFail":\s{0,100}"({failure_reason}[^"]+)""",
  ]

```