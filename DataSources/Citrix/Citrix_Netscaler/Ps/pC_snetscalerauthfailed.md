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
    """Browser\s{1,100}(.+?\(?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|iPhone).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|AppleWebKit))""",
  ]
}
```