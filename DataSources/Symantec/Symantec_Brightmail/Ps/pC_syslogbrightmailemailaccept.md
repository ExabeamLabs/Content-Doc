#### Parser Content
```Java
{
Name = syslog-brightmail-email-accept
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """|ACCEPT|""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}\w+\[\d{1,100}\]:""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|ACCEPT\|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})""",
    ]
  }
}
```