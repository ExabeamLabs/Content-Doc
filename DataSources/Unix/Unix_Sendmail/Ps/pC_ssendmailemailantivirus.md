#### Parser Content
```Java
{
Name = s-sendmail-email-antivirus
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """AntiVirus:""", """ classification=""" ]
  Fields = [
    """({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}) ({host}[\w.\-]{1,2000}) \S+ \[.+?\-({alert_id}\w+)\]""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({av_vendor}\S+)\.AntiVirus:""",
    """\sclassification=({malware_score}[^,]{1,2000})""",
  ]
}
```