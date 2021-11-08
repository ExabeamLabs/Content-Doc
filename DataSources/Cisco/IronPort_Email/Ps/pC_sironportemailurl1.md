#### Parser Content
```Java
{
Name = s-ironport-email-url-1
    Vendor = Cisco
  Product = IronPort Email
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """MID """, """URL Reputation Rule""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\srt=({time}\d{1,100})""",
      """({time}\w+ \d{1,100} \d\d:\d\d:\d\d) mail_logs:""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """MID ({alert_id}\d{1,100})""",
      """URL ({url}.+?) has reputation ({url_score}.+?) matched Condition: URL Reputation Rule"""
    ]
  }
```