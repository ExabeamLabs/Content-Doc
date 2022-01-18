#### Parser Content
```Java
{
Name = s-juniper-pulse-activity
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """WEB20174""", """WebRequest completed""" ]
  Fields = [
    """\stime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)"""",
    """\s{1,100}vpn=({host}[^\s]{1,2000})\s"""
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})\s{1,100}""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}[^\s]{1,2000})""",
    """\sdstname=({app}.+?)\s{1,100}\w+=""",
    """\sdstname=({dest_host}[^\s]{1,2000})""",
    """\ssent\\*=({bytes}\d{1,100})""",
    """Cmd\\*=({activity}[^\s&"]{1,2000})""",
    """User\\*=({user}[^\s&"]{1,2000})""",
    """DeviceType\\*=({src_host}[^"&]{1,2000})""",
    """agent="({user_agent}[^"]{1,2000})"""",
    """agent="({browser}[\w\-]{1,2000})""",
    """agent="({browser}[\w\-]{1,2000})\/[\d\._]{1,2000}""",
    """agent="(({browser}[^\/]{1,2000}).+)?({os}iOS|Android|BlackBerry|Mac OS X|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """agent="Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """agent="Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+)""",
   ]


}
```