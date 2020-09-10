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
      """\srt=({time}\d+)""",
      """\sdvc=({host}[\d.]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sshost=({src_host}[^\s]+)""",
      """\ssrc=({src_ip}[^\s]+)""",
      """\sdhost=({dest_host}[^\s]+)""",
      """\sdst=({dest_ip}[^\s]+)""",
      """\seventId=({alert_id}\d+)""",
      """\smsg=({alert_name}.+?)\s+\w+=""",
      """CEF:(.+?\|){6}({alert_severity}[^|]+)""",
      """CEF:(.+?\|){5}({alert_type}[^|]+)""",
      """\ssuser=(?:<>|<?({orig_user}.+?)>?)\s+\w+=""",
      """\sduser=(?:<>|({recipients_unfixed}.+?))\s+\w+=""",
      """\sduser=<?({external_address}[^\s>,]+)""",
      """\sduser=<?[^@]+@({external_domain}[^\s>,]+)""",
      """\sapp=({protocol}.+?)\s+\w+=""",
      """\sdeviceDirection=({direction_code}\d+)""",
      """\scs6=({subject}.+?)\s+(?:cs6Label=email-subject|\w+=.*cs6Label=email-subject)""",
      """cs6Label=email-subject.*\scs6=({subject}.+?)\s+\w+=""",
      """\scs4=({attachment}.+?)\s+(?:cs4Label=email-attachments|\w+=.*cs4Label=email-attachments)""",
      """cs4Label=email-attachments.*\scs4=({attachment}.+?)\s+\w+=""",
      """\sflexNumber1=({outcome_code}.+?)\s+(?:flexNumber1Label=reason-id|\w+=.*flexNumber1Label=reason-id)""",
      """flexNumber1Label=reason-id.*\sflexNumber1=({outcome_code}.+?)\s+\w+=""",
      """\sfsize=({bytes}\d+)""",
      """\scn3=({num_recipients}\d+)"""   
      """\sfilePath=(({file_path}[^\s]+\\)?({file_name}[^\s]+\.({file_ext}[^\s]+)))""", 
    ]
    DupFields = [ "orig_user->sender", "orig_user->user" ]
  }
```