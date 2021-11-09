#### Parser Content
```Java
{
Name = s-ironport-email-subject
    Vendor = Cisco
    Product = IronPort Email
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """MID """, """ Subject """ ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\srt=({time}\d{1,100})""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """MID ({alert_id}\d{1,100}) Subject '?({subject}[^']{1,2000}?)\s{0,100}('|$)"""
    ]
  }
}
```