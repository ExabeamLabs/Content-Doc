#### Parser Content
```Java
{
Name = syslog-brightmail-email-attachment-1
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """|ATTACH|""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}\w+\[\d{1,100}\]:""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|ATTACH\|({attachments}({attachment}[^\|\s]{1,2000}).*?)\s{0,100}$"""
    ]
  }
}
```