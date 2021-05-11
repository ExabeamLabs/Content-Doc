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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """CEF:([^\|]*\|){2}({alert_type}[^\|]+)\|[^\|]*\|({alert_id}[^\|]+)\|[^\|]*\|({alert_severity}[^\|]+)\|""",
    """\Wrt=({time}\d{1,100})""",
    """\Wcs1=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_email}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```