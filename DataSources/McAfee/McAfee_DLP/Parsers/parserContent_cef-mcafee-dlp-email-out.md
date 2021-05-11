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
      """\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\-\.]+)\s{0,100}""",
      """(\s|\|)rt=({time}\d{1,100})""",
      """CEF:([^|]+?\|){5}({alert_type}[^|]+)""",
      """CEF:([^|]+?\|){6}({alert_severity}[^|]+)""",
      """(\s|\|)app=({protocol}.+?)\s{1,100}\w+=""",
      """(\s|\|)msg=({alert_name}.+?)\s{0,100}(\w+=|$)""",
      """(\s|\|)dst=({dest_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)dhost=({dest_host}[^\s]+)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)shost=({src_host}[^\s]+)""",
      """(\s|\|)suser=(?:<>|<?({sender}[^\s>]+)>?)\s{0,100}(\w+=|$)""",
      """(\s|\|)duser=({recipients}.*?)\s{0,100}(\w+=|$)""",
      """(\s|\|)duser=<({external_address}[^@<]+@?({external_domain}[^\s,>]+))>""",
      """(\s|\|)fsize=({bytes}\d{1,100})""",
      """\scs4=({attachment}.+?)\s{0,100}(\w+=|$)""",
      """\scs6=({subject}.+?)\s{0,100}(\w+=|$)""",
      """\scn3=({num_recipients}\d{1,100})""",
      """\scn2=({num_attachments}\d{1,100})""", 
      """\sfilePath=(({file_path}[^\s]+\\)?({file_name}[^\s]+\.({file_ext}[^\s]+)))""",
    ]
    DupFields = [ "sender->user" ]
  }
```