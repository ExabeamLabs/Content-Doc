#### Parser Content
```Java
{
Name = s-vontu-dlp-email-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,blocked="""", """,rules="""", """,subject="""", """incident_id="""", """,mtchcnt="""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """({host}[\w\-.]+)\s{1,100}incident_id=""",
    """\Wincident_id="({alert_id}\d{1,100})""",
    """\Wblocked="({outcome}[^",]+)"""
    """\Wpolicy="({alert_name}[^"]+)""",
    """\Wpolicy="[^"\-]+\-\s{0,100}({alert_type}[^"]+)""",
    """\Wpolicy="[^"\-]+\-\s{0,100}({protocol}[^"]+)""",
    """\Wrecipients="({recipients}[^"]+)""",
    """\Wrecipients="({external_address}[^,"]+)""",
    """\Wrecipients="[^@]+@({external_domain}[^,"]+)""",
    """\Wsender="({user}[^@"]+)""",
    """\Wsender="({sender}[^"]+)""",
    """\Wseverity="({alert_severity}[^"]+)""",
    """\Wsubject="({subject}[^"]+)"""
  ]
}
```