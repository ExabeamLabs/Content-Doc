#### Parser Content
```Java
{
Name = fortinet-utm-app-activity
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd';time='HH:mm:ss"
  Conditions = [ """;subtype=app-ctrl;""", """;devname=""",""";vd=""", """;date=""", """;applist=""" ]
  Fields = [
    """date=({time}\d\d\d\d-\d\d-\d\d;time=\d\d:\d\d:\d\d)""",
    """devname=({host}[\w\-\.]{1,2000})""",
    """subtype=({event_subtype}[^;]{1,2000})""",
    """srcip=({src_ip}[a-fA-F\d:\.]{1,2000})""",
    """dstip=({dest_ip}[a-fA-F\d:\.]{1,2000})""",
    """srcport=({src_port}\d{1,5})""",
    """dstport=({dest_port}\d{1,5})""",
    """;srcintf=({src_interface}[^;]{1,2000})""",
    """;dstintf=({dest_interface}[^;]{1,2000})""",
    """;proto=({protocol}\d{1,5})""",
    """direction=({direction}[^;]{1,2000})""",
    """policyid=({policy_id}\d{1,100})""",
    """;app=({app}[^;]{1,2000})""",
    """action=({action}[^;]{1,2000})""",
    """hostname=({web_domain}[^;]{1,2000})""",
    """;appcat=({category}[^;]{1,2000})""",
    """;url=({uri_path}\/[^;]{1,2000})""",
    """subtype=({event_name}[^;]{1,2000})"""
  ]
  DupFields = [ "action->activity" ]


}
```