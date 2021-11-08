#### Parser Content
```Java
{
Name = s-sendmail-email-client
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ msg_direction=""", """ client_hostname=""", """ client_ip=""" ]
  Fields = [
    """({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}) ({host}[\w.\-]{1,2000}) \S+ \[.+?\-({alert_id}\w+)\]""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\smsg_direction=({direction}[^,]{1,2000})""",
  ]
}
```