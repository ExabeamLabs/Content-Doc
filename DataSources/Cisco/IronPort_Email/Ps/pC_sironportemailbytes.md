#### Parser Content
```Java
{
Name = s-ironport-email-bytes
    Vendor = Cisco
    Product = IronPort Email
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"  
    Conditions = [ """MID """, """ ready """, """ bytes from <""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\srt=({time}\d{1,100})""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """MID ({alert_id}\d{1,100})""",
      """({bytes}\d{1,100}) bytes from <({sender}[^@>]{1,2000}@[^>]{1,2000})>"""
    ]
  }
```