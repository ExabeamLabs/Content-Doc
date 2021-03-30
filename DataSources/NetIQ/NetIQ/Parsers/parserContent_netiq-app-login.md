#### Parser Content
```Java
{
Name = netiq-app-login
  Vendor = NetIQ
  Lms = QRadar
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """"NetIQ Access Manager"""", """User session""", """ siem: {""" ]
  Fields = [
    """\Wdt"*:"*({time}\d+)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[A-Fa-f:\d.]+)""",
    """\Wsun"*:"*({user}[^\s,"]+)""",
    """\Wcn=({user}[^\s,]+)""",
    """Client IP Address:\s*\[({src_ip}[A-Fa-f:\d.]+)""",
    """\WReason:\s*\[({failure_reason}[^\]]+?)\s*\]""",
    """((U|u)ser\s*Agent)\\"*:\\"*({user_agent}[^"]+?)\\*"""",
    """((U|u)ser\s*Agent)\\"*:\\"*(?:-|Mozilla\\?\/.+\(.*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """({app}NetIQ)""",
 ]
}
```