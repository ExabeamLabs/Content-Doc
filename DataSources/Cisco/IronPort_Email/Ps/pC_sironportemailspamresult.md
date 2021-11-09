#### Parser Content
```Java
{
Name = s-ironport-email-spam-result
    Vendor = Cisco
    Product = IronPort Email
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """MID """, """CASE spam""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\srt=({time}\d{1,100})""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """MID ({alert_id}\d{1,100})""",
      """CASE spam ({spam_score}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
    ]
  }
}
```