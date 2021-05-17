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
      """\sdvc=({host}[\d.]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sshost=({src_host}[^\s]{1,2000})""",
      """\ssrc=({src_ip}[^\s]{1,2000})""",
      """\sdhost=({dest_host}[^\s]{1,2000})""",
      """\sdst=({dest_ip}[^\s]{1,2000})""",
      """\seventId=({alert_id}\d{1,100})""",
      """\smsg=({alert_name}.+?)\s{1,100}\w+=""",
      """CEF:([^|]{1,2000}?\|){6}({alert_severity}[^|]{1,2000})""",
      """CEF:([^|]{1,2000}?\|){5}({alert_type}[^|]{1,2000})""",
      """\ssuser=(?:<>|<?({orig_user}.+?)>?)\s{1,100}\w+=""",
      """\sduser=(?:<>|({recipients_unfixed}.+?))\s{1,100}\w+=""",
      """\sduser=<?({external_address}[^\s>,]{1,2000})""",
      """\sduser=<?[^@]{1,2000}@({external_domain}[^\s>,]{1,2000})""",
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
      """\sfilePath=(({file_path}[^\s]{1,2000}\\)?({file_name}[^\s]{1,2000}\.({file_ext}[^\s]{1,2000})))""", 
    ]
    DupFields = [ "orig_user->sender", "orig_user->user" ]
  }
```