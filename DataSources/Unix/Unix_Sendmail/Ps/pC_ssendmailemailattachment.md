#### Parser Content
```Java
{
Name = s-sendmail-email-attachment
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ attach_name=""", """ attach_type=""", """ attach_filename=""" ]
  Fields = [
    """({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}) ({host}[\w.\-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\smtaqid=({alert_id}[^,]{1,2000})""",
    """\sattach_filename="({attachment}[^"]{1,2000})""",
  ]
}
```