#### Parser Content
```Java
{
Name = cef-guardium-database-alert
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = ArcSight
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|IBM|Guardium|""", """cs3Label=Database Name""", """deviceSeverity=""" ]
  Fields = [
    """CEF:([^|]*\|){5}({alert_name}[^|]+)""",
    """CEF:([^|]*\|){6}({alert_severity}[^|]+)""",
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsuser=({user}[^\s]+)""",
    """\Wcs3=(|({database_name}.+?))\s*(\w+=|$)""",
    """\Wcs2=({server_group}.+?)\s*(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=(({domain}[^\\]+)\\+)?({src_host}[^\\\s]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wcn1=({response_size}\d+)""",
    """\WdeviceSeverity=({device_severity}\d+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```