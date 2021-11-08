#### Parser Content
```Java
{
Name = s-sendmail-email-recipients
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ displayname=""", """ connectingip=""", """ envelopesender=""" ]
  Fields = [
    """({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}) ({host}[\w.\-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sqid="({alert_id}[^"]{1,2000})""",
    """\srecipients="({recipient}[^"]{1,2000}?@[^",;]{1,2000})""",
    """\srecipients="({recipients}[^"]{1,2000})""",
    """\ssubject="({subject}.+?)"(,\s|\s{0,100}$)""",
  ]
}
```