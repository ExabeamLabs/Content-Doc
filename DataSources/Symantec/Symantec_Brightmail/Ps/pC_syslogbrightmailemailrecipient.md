#### Parser Content
```Java
{
Name = syslog-brightmail-email-recipient
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """|ORCPTS|""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}\w+\[\d{1,100}\]:""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|ORCPTS\|({recipients}({recipient}[^\|\s]{1,2000}).*?)\s{0,100}$"""
    ]
  }
```