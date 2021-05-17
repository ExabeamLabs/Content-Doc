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
      """\s({host}[^.\s]{1,2000})(\.\w+)*\s{0,100}(Message =)? ID:\s({alert_id}\d{1,100})""",
      """Sender:\s{1,100}({user}[^@]{1,2000})""",
      """Sender:\s{1,100}({sender}[^,]{1,2000})""",
      """Subject:\s{1,100}({subject}.+?),\s{1,100}Target:""",
      """Recipient:\s{1,100}({recipients}.+?),\s{1,100}Sender:""",
      """Recipient:\s{1,100}({external_address}[^,]{1,2000}),""",
      """Recipient:\s{1,100}[^@]{1,2000}@({external_domain}[^,]{1,2000}),""",
      """Severity:\s{1,100}({alert_severity}.+?),\s{1,100}Subject:""",
      """Policy Violated:\s{1,100}({alert_name}.+?),\s{1,100}Count:""",
      """Protocol:\s{1,100}(({alert_type}[^,]{1,2000}))""",
      """Protocol:\s{1,100}(({protocol}[^,]{1,2000}))""",
      """({direction}o)""",
      """\sBlocked:\s{1,100}({outcome}[^\s,]{1,2000})"""
    ]
  }
```