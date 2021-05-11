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
    """({host}[\w\-.]+)\s{1,100}({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+) [^\s]+""",
    """({host}[\w\-.]+)\s{1,100}({time}\d\d\d\d\/\d\d\/\d\d:\d\d:\d\d:\d\d \w+) [^\s]+""",
    """User\s{1,100}({user}[^\s]+)""",
    """Client_ip\s{1,100}({src_ip}[A-Fa-f:\d.]+)""",
    """Failure_reason\s{0,100}"({failure_reason}[^"]+)""",
    """Browser\s{1,100}(.+?\(?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|iPhone).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|AppleWebKit))""",
  ]
}
```