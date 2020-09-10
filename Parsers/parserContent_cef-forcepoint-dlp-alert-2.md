#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-alert-2
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint CASB|""", """sourceServiceName=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """CEF:([^\|]*\|){2}({alert_type}[^\|]+)\|[^\|]*\|({alert_id}[^\|]+)\|[^\|]*\|({alert_severity}[^\|]+)\|""",
    """\Wrt=({time}\d+)""",
    """\Wcs1=({alert_name}.+?)\s+(\w+=|$)""",
    """\Wduser=({user_email}.+?)\s+(\w+=|$)""",
    """\Wsuser=({user}.+?)\s+(\w+=|$)""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
  ]
}
```