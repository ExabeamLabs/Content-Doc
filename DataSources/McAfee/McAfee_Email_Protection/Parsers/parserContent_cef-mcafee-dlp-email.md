#### Parser Content
```Java
{
Name = cef-mcafee-dlp-email
    Vendor = McAfee
    Product = McAfee Email Protection
    Lms = ArcSight
    DataType = "dlp-email-alert"
    TimeFormat = "epoch"
    Conditions = [ "CEF:", "|McAfee|Email Gateway|", "Label=email-subject " ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}[\d.]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sshost=({src_host}[^\s]+)""",
      """\ssrc=({src_ip}[^\s]+)""",
      """\sdhost=({dest_host}[^\s]+)""",
      """\sdst=({dest_ip}[^\s]+)""",
      """\seventId=({alert_id}\d{1,100})""",
      """\smsg=({alert_name}.+?)\s{1,100}\w+=""",
      """CEF:([^|]+?\|){6}({alert_severity}[^|]+)""",
      """CEF:([^|]+?\|){5}({alert_type}[^|]+)""",
      """\ssuser=(?:<>|<?({orig_user}.+?)>?)\s{1,100}\w+=""",
      """\sduser=(?:<>|({recipients_unfixed}.+?))\s{1,100}\w+=""",
      """\sduser=<?({external_address}[^\s>,]+)""",
      """\sduser=<?[^@]+@({external_domain}[^\s>,]+)""",
      """\sapp=({protocol}.+?)\s{1,100}\w+=""",
      """\sdeviceDirection=({direction_code}\d{1,100})""",
      """\scs6=({subject}.+?)\s{1,100}(?:cs6Label=email-subject|\w+=.*cs6Label=email-subject)""",
      """cs6Label=email-subject.*\scs6=({subject}.+?)\s{1,100}\w+=""",
      """\scs4=({attachment}.+?)\s{1,100}(?:cs4Label=email-attachments|\w+=.*cs4Label=email-attachments)""",
      """cs4Label=email-attachments.*\scs4=({attachment}.+?)\s{1,100}\w+=""",
      """\sflexNumber1=({outcome_code}.+?)\s{1,100}(?:flexNumber1Label=reason-id|\w+=.*flexNumber1Label=reason-id)""",
      """flexNumber1Label=reason-id.*\sflexNumber1=({outcome_code}.+?)\s{1,100}\w+=""",
      """\sfsize=({bytes}\d{1,100})""",
      """\scn3=({num_recipients}\d{1,100})"""   
      """\sfilePath=(({file_path}[^\s]+\\)?({file_name}[^\s]+\.({file_ext}[^\s]+)))""", 
    ]
    DupFields = [ "orig_user->sender", "orig_user->user" ]
  }
```