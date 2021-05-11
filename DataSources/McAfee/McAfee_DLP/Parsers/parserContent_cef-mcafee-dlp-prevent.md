#### Parser Content
```Java
{
Name = cef-mcafee-dlp-prevent
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "epoch"
    Conditions = [ "CEF:", "|McAfee|DLP Prevent|"]
    Fields = [
      """\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\-\.]+)\s{0,100}""",
      """(\s|\|)rt=({time}\d{1,100})""",
      """CEF:([^|]+?\|){5}({alert_type}[^|]+)""",
      """CEF:([^|]+?\|){6}({alert_severity}[^|]+)""",
      """(\s|\|)app=({protocol}.+?)\s{1,100}\w+=""",
      """(\s|\|)msg=(\s{1,100}|(({alert_name}.+?)\s{0,100}))(\w+=|$)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)shost=({src_host}[^\s]+)""",
      """(\s|\|)suser=<?({sender}[^\s@<>]+?@[^\s@<>]+)"""
      """(\s|\|)duser=<?({recipient}[^\s@<>]+?@({external_domain}[^\s@<>]+))"""
      """(\s|\|)duser=(\s{1,100}|(({recipients}.+?)\s{0,100}))(\w+=|$)""",
      """(\s|\|)fsize=({bytes}\d{1,100})""",
      """\scs4=(\s{1,100}|(({attachments}.+?)\s{0,100}))(\w+=|$)""",
      """\scs6=(\s{1,100}|(({subject}.+?)\s{0,100}))(\w+=|$)""",
      """\scn3=({num_recipients}\d{1,100})"""
      """(\s|\|)sMcAfeeDLPEmailSender=<?({sender}[^\s@<>]+?@[^\s@<>]+)"""
      """(\s|\|)sMcAfeeDLPEmailRecipients=<?({recipient}[^\s@<>]+?@({external_domain}[^\s@<>]+))"""      
      """\sMcAfeeDLPEmailRecipients=(\s{1,100}|((recipients}.+?)\s{0,100}))(\w+=|$)"""
      """\sMcAfeeDLPHostDomainName=({domain}[\w\-\.]+?)\s{0,100}(\w+=|$)"""
      """\sMcAfeeDLPHostName=({host}[\w\-\.]+?)\s{0,100}(\w+=|$)"""
      """({additional_info}Unable to deliver message.)"""
    ]
    DupFields = [ "sender->user_email", "recipient->external_address" ]
  }
```