#### Parser Content
```Java
{
Name = cef-mcafee-dlp-email-out
    Vendor = McAfee
    Product = McAfee DLP
    Lms = ArcSight
    DataType = "dlp-email-alert"
    TimeFormat = "epoch"
    Conditions = [ "|McAfee|DLP Prevent|", """The content was categorized as protected content""" ]
    Fields = [
      """\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s*({host}[\w\-\.]+)\s*""",
      """(\s|\|)rt=({time}\d+)""",
      """CEF:(.+?\|){5}({alert_type}[^|]+)""",
      """CEF:(.+?\|){6}({alert_severity}[^|]+)""",
      """(\s|\|)app=({protocol}.+?)\s+\w+=""",
      """(\s|\|)msg=({alert_name}.+?)\s*(\w+=|$)""",
      """(\s|\|)dst=({dest_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)dhost=({dest_host}[^\s]+)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)shost=({src_host}[^\s]+)""",
      """(\s|\|)suser=(?:<>|<?({sender}[^\s>]+)>?)\s*(\w+=|$)""",
      """(\s|\|)duser=({recipients}.*?)\s*(\w+=|$)""",
      """(\s|\|)duser=<({external_address}[^@<]+@?({external_domain}[^\s,>]+))>""",
      """(\s|\|)fsize=({bytes}\d+)""",
      """\scs4=({attachment}.+?)\s*(\w+=|$)""",
      """\scs6=({subject}.+?)\s*(\w+=|$)""",
      """\scn3=({num_recipients}\d+)"""
    ]
    DupFields = [ "sender->user" ]
  }
```