#### Parser Content
```Java
{
Name = netiq-app-login
  Vendor = NetIQ
  Product = NetIQ
  Lms = QRadar
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """"NetIQ Access Manager"""", """User session""", """ siem: {""" ]
  Fields = [
    """\Wdt"{0,20}:"{0,20}({time}\d{1,100})""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wsun"{0,20}:"{0,20}({user}[^\s,"]{1,2000})""",
    """\Wcn=({user}[^\s,]{1,2000})""",
    """Client IP Address:\s{0,100}\[({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WReason:\s{0,100}\[({failure_reason}[^\]]{1,2000}?)\s{0,100}\]""",
    """((U|u)ser\s{0,100}Agent)\\"{0,20}:\\"{0,20}({user_agent}[^"]{1,2000}?)\\*"""",
    """((U|u)ser\s{0,100}Agent)\\"{0,20}:\\"{0,20}(?:-|Mozilla\\?\/.+\(.*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """({app}NetIQ)""",
 ]


}
```