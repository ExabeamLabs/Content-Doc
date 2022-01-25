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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d),? (::ffff:)?({host}[\w\-.]{1,2000})""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s\w+\s(::ffff:)?({host}[^\s]{1,2000})""",
    """ attack ({alert_type}[^\s:]{1,2000})""",
    """ attack ({alert_type}[^\s:]{1,2000}):\s{0,100}({alert_name}.+?)\s{0,100}\(""",
    """severity\s{0,100}=\s{0,100}(N\/A|({alert_severity}[^\)]{1,2000}))\)""",
    """\s(::ffff:)?(N\/A|({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f\d]{0,100}:[A-Fa-f\d:]{1,2000}))):(N\/A|({src_port}\d{1,100})) -> (::ffff:)?(N\/A|({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f\d]{0,100}:[A-Fa-f\d:]{1,2000}))):(N\/A|({dest_port}\d{1,100}))\s""",
    """\sprotocol\s{0,100}(N\/A|({protocol}[^\s]{1,2000}))\s""",
    """\svirusname\s{0,100}(N\/A|({virusname}[^\s]{1,2000}))\s""",
    """\(result\s{0,100}=\s{0,100}(n\/a|({outcome}[^\)]{1,2000}))\)""",
    """\sdetected\s(Unknown|({direction}[^\s]{1,2000}))\s""",
    """\d\d:\d\d:\d\d\s{1,100}(::ffff:)?\s{0,100}({host}[A-Fa-f:\d.]{1,2000})\s{1,100}\w+"""
  ]


}
```