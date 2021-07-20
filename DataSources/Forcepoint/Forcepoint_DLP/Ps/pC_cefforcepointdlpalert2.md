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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """CEF:([^\|]{0,2000}\|){2}({alert_type}[^\|]{1,2000})\|[^\|]{0,2000}\|({alert_id}[^\|]{1,2000})\|[^\|]{0,2000}\|({alert_severity}[^\|]{1,2000})\|""",
    """\Wrt=({time}\d{1,100})""",
    """\Wcs1=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_email}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```