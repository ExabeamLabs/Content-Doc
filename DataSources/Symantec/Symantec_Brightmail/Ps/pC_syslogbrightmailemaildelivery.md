#### Parser Content
```Java
{
Name = syslog-brightmail-email-delivery
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """|DELIVER""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}\w+\[\d{1,100}\]:""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|(|({outcome}[^\|]{1,2000}))\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,100}\|(|({recipient}[^@]{1,2000}@[^@]{1,2000}?))(\||\s{0,100}$)""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|(|({outcome}[^\|]{1,2000}))\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,100}\|(|({failure_reason}[^\|]{1,2000}))\|(|({recipient}[^@]{1,2000}@[^@]{1,2000}?))(\||\s{0,100}$)"""
    ]
  }
}
```