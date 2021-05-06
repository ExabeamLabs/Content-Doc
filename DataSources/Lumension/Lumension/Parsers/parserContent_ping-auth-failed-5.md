#### Parser Content
```Java
{
Name = ping-auth-failed-5
  DataType = "authentication-failed"
  Conditions = [ """| OAuth|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s*(AUTHN_ATTEMPT|OAuth|SSO)\s*\|)\s*([^\|]*\|){9}\s*(|({failure_reason}[^\|]*?))\s*\|""",
  ]
}
ping-events = {
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Splunk
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Fields = [
    """"Time":\s*"*({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d+)""",
    """"duid":\s*"(({domain}[^"@\\\/]+)[\\\/]+)?({user}[^@"\\\/]+)"""",
    """"duid":\s*"({user_email}[^"\s@]+@[^"\s@]+)""""
    """"SRCIP":\s*"({src_ip}[a-fA-F\d.:]+)""",
    """"remoteAddr":\s*"({dest_ip}[a-fA-F\d.:]+)""",
    """"Status":\s*"({outcome}[^"]+)""",
    """"Protocol":\s*"({protocol}[^"]+)""",
    """"PingHost":\s*"({host}[^"]+)""",
    """"EventType":\s*"({activity}[^"]+)""",
    """"DescriptionFail":\s*"({failure_reason}[^"]+)""",
  ]

```