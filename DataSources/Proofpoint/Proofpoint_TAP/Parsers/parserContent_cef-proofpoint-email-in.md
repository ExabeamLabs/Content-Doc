#### Parser Content
```Java
{
Name = cef-proofpoint-email-in
    Vendor = Proofpoint
    Product = Proofpoint TAP
    Lms = ArcSight
    DataType = "dlp-email-alert"
    TimeFormat = "epoch"
    Conditions = [ """|Proofpoint|TAP|""" ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """exabeam_host=({host}[\w.\-]+)""",
      """^([^|]*\|){4}({outcome}[^|]+)""",
      """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
      """\ssuser=({sender}\S+)""",
      """\ssuser=\S+@({external_domain}\S+)""",
      """\sduser=({user}\S+)""",
      """({alert_name}Proofpoint)""",
      """"threatType":"({alert_type}[^"]+)""",
      """"threatID":"({alert_id}[^"]+)""",
      """\scs6=\[({additional_info}[^\]]+)"""
    ]
    DupFields = [ 
      "user->recipients",
      "sender->external_address",
    ]
  }
```