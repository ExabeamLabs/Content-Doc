#### Parser Content
```Java
{
Name = q-sendmail-dlp-email-alert
  Vendor = Unix
  Product = Unix Sendmail
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[Web] Sent e-mail""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\]:\s{0,100}\(({src_ip}[a-fA-F:\d.]{1,2000}).*?\[Web\] Sent e-mail""",
    """User:\s{0,100}({sender}[^\s\)]{1,2000})""",
    """Subject:\s{0,100}({subject}.+?);\s{0,100}To:""",
    """To:\s{0,100}({recipients}.+?)\s{1,100}with files:""",
    """To:\s{0,100}({recipient}[^\s,]{1,2000})""",
    """files:\s{0,100}.*?[\\\/]{0,2000}({file_name}[^\\\/]{1,2000}?)\s{0,100}\(""",
    """files:\s{0,100}({attachments}.+?)\s{0,100}$""",
    """files:\s{0,100}.*?[\\\/]{0,2000}({attachment}.+?)\s{0,100}\(({bytes_num}[\d\.]{1,2000})\s{0,100}({bytes_unit}[^\s\)]{1,2000})""",
  ]


}
```