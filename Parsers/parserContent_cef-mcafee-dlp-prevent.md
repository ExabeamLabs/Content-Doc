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
      """\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s*({host}[\w\-\.]+)\s*""",
      """(\s|\|)rt=({time}\d+)""",
      """CEF:(.+?\|){5}({alert_type}[^|]+)""",
      """CEF:(.+?\|){6}({alert_severity}[^|]+)""",
      """(\s|\|)app=({protocol}.+?)\s+\w+=""",
      """(\s|\|)msg=(\s+|(({alert_name}.+?)\s*))(\w+=|$)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)shost=({src_host}[^\s]+)""",
      """(\s|\|)suser=<?({sender}[^\s@<>]+?@[^\s@<>]+)"""
      """(\s|\|)duser=<?({recipient}[^\s@<>]+?@({external_domain}[^\s@<>]+))"""
      """(\s|\|)duser=(\s+|(({recipients}.+?)\s*))(\w+=|$)""",
      """(\s|\|)fsize=({bytes}\d+)""",
      """\scs4=(\s+|(({attachments}.+?)\s*))(\w+=|$)""",
      """\scs6=(\s+|(({subject}.+?)\s*))(\w+=|$)""",
      """\scn3=({num_recipients}\d+)"""
      """(\s|\|)sMcAfeeDLPEmailSender=<?({sender}[^\s@<>]+?@[^\s@<>]+)"""
      """(\s|\|)sMcAfeeDLPEmailRecipients=<?({recipient}[^\s@<>]+?@({external_domain}[^\s@<>]+))"""      
      """\sMcAfeeDLPEmailRecipients=(\s+|((recipients}.+?)\s*))(\w+=|$)"""
      """\sMcAfeeDLPHostDomainName=({domain}[\w\-\.]+?)\s*(\w+=|$)"""
      """\sMcAfeeDLPHostName=({host}[\w\-\.]+?)\s*(\w+=|$)"""
      """({additional_info}Unable to deliver message.)"""
    ]
    DupFields = [ "sender->user_email", "recipient->external_address" ]
  }
```