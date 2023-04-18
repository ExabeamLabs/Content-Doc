#### Parser Content
```Java
{
Name = s-netscaler-auth-failed
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """Client_ip""", """Failure_reason""", """LOGIN_FAILED"""]
  Fields = [
    """({host}[\w\-.]{1,2000})\s{1,100}({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+) [^\s]{1,2000}""",
    """({host}[\w\-.]{1,2000})\s{1,100}({time}\d\d\d\d\/\d\d\/\d\d:\d\d:\d\d:\d\d \w+) [^\s]{1,2000}""",
    """User\s{1,100}({user}[^\s]{1,2000})""",
    """Client_ip\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Failure_reason\s{0,100}"({failure_reason}[^"]{1,2000})""",
    """Browser .*?({user_agent}[^"]{1,2000})""",
  ]


}
```