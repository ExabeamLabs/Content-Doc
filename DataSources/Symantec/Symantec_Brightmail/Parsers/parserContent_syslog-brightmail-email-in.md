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
      """\s({host}[\w\.-]+)\s+\S+\[\d+\]:""",
      """\s*({time}\d+)\|(|({alert_id}[^\|]+))\|VERDICT\|""",
      """\|ORCPTS\|({recipients}({recipient}[^\|]+).*?)\|ACCEPT\|""",
      """\|ACCEPT\|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+)""",
      """\|SENDER\|({sender}[^@\|]+@({external_domain}[^@\|]+))\|"""
    ]
    DupFields = [ "sender->external_address" ]
  }
```