#### Parser Content
```Java
{
Name = s-ironport-email-file-verdict
    Vendor = Cisco
  Product = IronPort Email
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """MID """, """file reputation verdict""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """\srt=({time}\d{1,100})""",
      """({time}\w+ \d{1,100} \d\d:\d\d:\d\d) mail_logs:""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """MID ({alert_id}\d{1,100})""",
      """file reputation verdict\s{0,100}:\s{0,100}(?:UNKNOWN|({file_verdict}[^,\s]{1,2000}))""",
    ]
  }
```