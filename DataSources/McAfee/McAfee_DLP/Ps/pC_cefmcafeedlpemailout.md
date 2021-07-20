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
      """\w{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\-\.]{1,2000})\s{0,100}""",
      """(\s|\|)rt=({time}\d{1,100})""",
      """CEF:([^|]{1,2000}?\|){5}({alert_type}[^|]{1,2000})""",
      """CEF:([^|]{1,2000}?\|){6}({alert_severity}[^|]{1,2000})""",
      """(\s|\|)app=({protocol}.+?)\s{1,100}\w+=""",
      """(\s|\|)msg=({alert_name}.+?)\s{0,100}(\w+=|$)""",
      """(\s|\|)dst=({dest_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)dhost=({dest_host}[^\s]{1,2000})""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)shost=({src_host}[^\s]{1,2000})""",
      """(\s|\|)suser=(?:<>|<?({sender}[^\s>]{1,2000})>?)\s{0,100}(\w+=|$)""",
      """(\s|\|)duser=({recipients}.*?)\s{0,100}(\w+=|$)""",
      """(\s|\|)duser=<({external_address}[^@<]{1,2000}@?({external_domain}[^\s,>]{1,2000}))>""",
      """(\s|\|)fsize=({bytes}\d{1,100})""",
      """\scs4=({attachment}.+?)\s{0,100}(\w+=|$)""",
      """\scs6=({subject}.+?)\s{0,100}(\w+=|$)""",
      """\scn3=({num_recipients}\d{1,100})""",
      """\scn2=({num_attachments}\d{1,100})""", 
      """\sfilePath=(({file_path}[^\s]{1,2000}\\)?({file_name}[^\s]{1,2000}\.({file_ext}[^\s]{1,2000})))""",
    ]
    DupFields = [ "sender->user" ]
  }
```