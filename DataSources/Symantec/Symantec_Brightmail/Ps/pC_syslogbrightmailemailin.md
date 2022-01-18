#### Parser Content
```Java
{
Name = syslog-brightmail-email-in
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """|VERDICT|""", """|ORCPTS|""", """|ACCEPT|""", """|SENDER|""", """|RECEIVED""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}\S+\[\d{1,100}\]:""",
      """\s{0,100}({time}\d{1,100})\|(|({alert_id}[^\|]{1,2000}))\|VERDICT\|""",
      """\|ORCPTS\|({recipients}({recipient}[^\|]{1,2000}).*?)\|ACCEPT\|""",
      """\|ACCEPT\|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})""",
      """\|SENDER\|({sender}[^@\|]{1,2000}@({external_domain}[^@\|]{1,2000}))\|"""
    ]
    DupFields = [ "sender->external_address" ]
  

}
```