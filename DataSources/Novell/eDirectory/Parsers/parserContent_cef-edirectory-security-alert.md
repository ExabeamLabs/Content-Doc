#### Parser Content
```Java
{
Name = cef-edirectory-security-alert
  DataType = "alert"
  Conditions = [ """CEF:""", """|eDirectory|eDirectory|""", """|INTRUDER_DETECTED|""" ]
  Fields = ${eDirectoryParserTemplates.cef-edirectory-events.Fields} [
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
cef-edirectory-events = {
  Vendor = Novell
  Product = eDirectory
  Lms = ArcSight
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """\Wrt=({time}\w+\s+\d+\s+\d+ \d\d:\d\d:\d\d)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wsuser=CN\\=({src_host}[\w\-.]+)""",
    """\Wduser=CN\\=({user_fullname}[^,]+),({user_ou}OU\\=.+?)\s+(\w+=|$)""",
    """\Woutcome=({outcome}\w+)""",
    """\Wcs1=(({protocol}\w+):\s*)?({dest_ip}[A-Fa-f:\d.]+?):({dest_port}\d+)""",
  ]

```