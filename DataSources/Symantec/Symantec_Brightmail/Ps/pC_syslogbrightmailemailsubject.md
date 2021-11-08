#### Parser Content
```Java
{
Name = syslog-brightmail-email-subject
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """|SUBJECT|""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}\w+\[\d{1,100}\]:""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|SUBJECT\|\s{0,100}(|({subject}.+?))(\||\s{0,100}$)""",
    ]
  }
```