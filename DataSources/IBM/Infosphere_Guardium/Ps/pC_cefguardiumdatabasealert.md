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
    """CEF:([^|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
    """CEF:([^|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000})""",
    """\Wcs3=(|({database_name}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs2=({server_group}.+?)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wshost=(({domain}[^\\]{1,2000})\\+)?({src_host}[^\\\s]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wcn1=({response_size}\d{1,100})""",
    """\WdeviceSeverity=({device_severity}\d{1,100})"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```