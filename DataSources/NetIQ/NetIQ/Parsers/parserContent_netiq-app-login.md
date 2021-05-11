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
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[A-Fa-f:\d.]+)""",
    """\Wsun"{0,20}:"{0,20}({user}[^\s,"]+)""",
    """\Wcn=({user}[^\s,]+)""",
    """Client IP Address:\s{0,100}\[({src_ip}[A-Fa-f:\d.]+)""",
    """\WReason:\s{0,100}\[({failure_reason}[^\]]+?)\s{0,100}\]""",
    """((U|u)ser\s{0,100}Agent)\\"{0,20}:\\"{0,20}({user_agent}[^"]+?)\\*"""",
    """((U|u)ser\s{0,100}Agent)\\"{0,20}:\\"{0,20}(?:-|Mozilla\\?\/.+\(.*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """({app}NetIQ)""",
 ]
}
```