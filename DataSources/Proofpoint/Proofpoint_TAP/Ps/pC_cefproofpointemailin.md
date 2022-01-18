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
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """^([^|]{0,2000}\|){4}({outcome}[^|]{1,2000})""",
      """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\ssuser=({sender}\S+)""",
      """\ssuser=\S+@({external_domain}\S+)""",
      """\sduser=({user}\S+)""",
      """({alert_name}Proofpoint)""",
      """"threatType":"({alert_type}[^"]{1,2000})""",
      """"threatID":"({alert_id}[^"]{1,2000})""",
      """\scs6=\[({additional_info}[^\]]{1,2000})"""
    ]
    DupFields = [ 
      "user->recipients",
      "sender->external_address",
    ]
  

}
```