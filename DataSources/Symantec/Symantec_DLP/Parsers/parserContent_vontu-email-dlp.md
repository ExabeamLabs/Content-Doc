#### Parser Content
```Java
{
Name = vontu-email-dlp
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "Policy Violated: ", "Protocol: SMTP,", "Subject: ", "Blocked: " ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({host}[^.\s]+)(\.\w+)*\s*(Message =)? ID:\s({alert_id}\d+)""",
      """Sender:\s+({user}[^@]+)""",
      """Sender:\s+({sender}[^,]+)""",
      """Subject:\s+({subject}.+?),\s+Target:""",
      """Recipient:\s+({recipients}.+?),\s+Sender:""",
      """Recipient:\s+({external_address}[^,]+),""",
      """Recipient:\s+[^@]+@({external_domain}[^,]+),""",
      """Severity:\s+({alert_severity}.+?),\s+Subject:""",
      """Policy Violated:\s+({alert_name}.+?),\s+Count:""",
      """Protocol:\s+(({alert_type}[^,]+))""",
      """Protocol:\s+(({protocol}[^,]+))""",
      """({direction}o)""",
      """\sBlocked:\s+({outcome}[^\s,]+)"""
    ]
  }
```