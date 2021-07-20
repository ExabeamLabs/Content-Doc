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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}incident_id=""",
    """\Wincident_id="({alert_id}\d{1,100})""",
    """\Wblocked="({outcome}[^",]{1,2000})"""
    """\Wpolicy="({alert_name}[^"]{1,2000})""",
    """\Wpolicy="[^"\-]{1,2000}\-\s{0,100}({alert_type}[^"]{1,2000})""",
    """\Wpolicy="[^"\-]{1,2000}\-\s{0,100}({protocol}[^"]{1,2000})""",
    """\Wrecipients="({recipients}[^"]{1,2000})""",
    """\Wrecipients="({external_address}[^,"]{1,2000})""",
    """\Wrecipients="[^@]{1,2000}@({external_domain}[^,"]{1,2000})""",
    """\Wsender="({user}[^@"]{1,2000})""",
    """\Wsender="({sender}[^"]{1,2000})""",
    """\Wseverity="({alert_severity}[^"]{1,2000})""",
    """\Wsubject="({subject}[^"]{1,2000})"""
  ]
}
```