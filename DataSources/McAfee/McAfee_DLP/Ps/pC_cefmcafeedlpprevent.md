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
      """\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\-\.]{1,2000})\s{0,100}""",
      """(\s|\|)rt=({time}\d{1,100})""",
      """CEF:([^|]{1,2000}?\|){5}({alert_type}[^|]{1,2000})""",
      """CEF:([^|]{1,2000}?\|){6}({alert_severity}[^|]{1,2000})""",
      """(\s|\|)app=({protocol}.+?)\s{1,100}\w+=""",
      """(\s|\|)msg=(\s{1,100}|(({alert_name}.+?)\s{0,100}))(\w+=|$)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)shost=({src_host}[^\s]{1,2000})""",
      """(\s|\|)suser=<?({sender}[^\s@<>]{1,2000}?@[^\s@<>]{1,2000})"""
      """(\s|\|)duser=<?({recipient}[^\s@<>]{1,2000}?@[^\s@<>]{1,2000})"""
      """(\s|\|)duser=(\s{1,100}|(({recipients}.+?)\s{0,100}))(\w+=|$)""",
      """(\s|\|)fsize=({bytes}\d{1,100})""",
      """\scs4=(\s{1,100}|(({attachments}.+?)\s{0,100}))(\w+=|$)""",
      """\scs6=(\s{1,100}|(({subject}.+?)\s{0,100}))(\w+=|$)""",
      """\scn3=({num_recipients}\d{1,100})"""
      """(\s|\|)sMcAfeeDLPEmailSender=<?({sender}[^\s@<>]{1,2000}?@[^\s@<>]{1,2000})"""
      """(\s|\|)sMcAfeeDLPEmailRecipients=<?({recipient}[^\s@<>]{1,2000}?@[^\s@<>]{1,2000})"""      
      """\sMcAfeeDLPEmailRecipients=(\s{1,100}|((recipients}.+?)\s{0,100}))(\w+=|$)"""
      """\sMcAfeeDLPHostDomainName =({domain}[\w\-\.]{1,2000}?)\s{0,100}(\w+=|$)"""
      """\sMcAfeeDLPHostName =({host}[\w\-\.]{1,2000}?)\s{0,100}(\w+=|$)"""
      """({additional_info}Unable to deliver message.)"""
    ]
    DupFields = [ "sender->user_email", "recipient->external_address" ]
  

}
```