#### Parser Content
```Java
{
Name = syslog-mcafee-network-alert
  Vendor = McAfee
  Product = McAfee NSM
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ detected """, """ attack """, """(severity = """, """(result = """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d),? (::ffff:)?({host}[\w\-.]+)""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s\w+\s(::ffff:)?({host}[^\s]+)""",
    """ attack ({alert_type}[^\s:]+)""",
    """ attack ({alert_type}[^\s:]+):\s*({alert_name}.+?)\s*\(""",
    """severity\s*=\s*(N\/A|({alert_severity}[^\)]+))\)""",
    """\s(::ffff:)?(N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})):(N\/A|({src_port}\d+)) -> (::ffff:)?(N\/A|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})):(N\/A|({dest_port}\d+))\s""",
    """\sprotocol\s*(N\/A|({protocol}[^\s]+))\s""",
    """\svirusname\s*(N\/A|({virusname}[^\s]+))\s""",
    """\(result\s*=\s*(n\/a|({outcome}[^\)]+))\)""",
    """\sdetected\s(Unknown|({direction}[^\s]+))\s""",
    """\d\d:\d\d:\d\d\s+(::ffff:)?\s*({host}[A-Fa-f:\d.]+)\s+\w+"""
  ]
}
```