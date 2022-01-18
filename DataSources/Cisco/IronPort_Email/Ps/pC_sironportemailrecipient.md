#### Parser Content
```Java
{
Name = s-ironport-email-recipient
    Vendor = Cisco
  Product = IronPort Email
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "ddd MMM dd HH:mm:ss yyyy"
    Conditions = [ """MID """, """ RID """, """ To: """ ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """\srt=({time}\d{1,100})""",
      """({time}\w+ \d{1,100} \d\d:\d\d:\d\d) mail_logs:""",
      """({time}\w+ \w+ \d{1,100} \d\d:\d\d:\d\d \d\d\d\d) Info: MID""",
      """MID ({alert_id}\d{1,100}) .*? To: <({recipient}[^@>,;]{1,2000}?@({external_domain_recipient}[^>,;]{1,2000}))""",
      """ To: <({recipients}[^>]{1,2000}?)>"""
    ]
  

}
```