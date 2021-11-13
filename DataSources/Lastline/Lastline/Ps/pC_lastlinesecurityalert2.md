#### Parser Content
```Java
{
Name = lastline-security-alert-2
  Conditions = [ """CEF:""", """|Lastline|""", """|email-attachment|""", """|Suspicious Email Attachment|""" ]

lastline-security-alert = {
    Vendor = Lastline
    Product = Lastline
    Lms = ArcSight
    DataType = "security-alert"
    TimeFormat = "epoch"
    Fields = [
          """\srt=({time}\d{1,100})""",
          """\sshost=((\d{1,100}[-.]){3}\d{1,100}[^\s]{1,2000}|({src_host}[^=]{1,2000}?))\s{0,100}\w+=""",
          """\ssrc=({src_ip}[\da-fA-F.:]{1,2000})""",
          """\sdhost=((\d{1,100}[-.]){3}\d{1,100}[^\s]{1,2000}|({dest_host}[^=]{1,2000}?))\s{0,100}\w+=""",
          """\sdst=({dest_ip}[\da-fA-F.:]{1,2000})""",
          """CEF[^|]{1,2000}\|([^|]{0,2000}\|){4}({alert_name}.+?)\s{0,100}\|(Unknown|({alert_severity}[^|]{1,2000}?))\|\s{0,100}(\w+=|$)""",
          """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})""",
          """cat=({alert_type}[^=]{1,2000}?)\s{1,100}\w+=""",
          """\sproto=({protocol}[^=]{1,2000}?)\s{0,100}\w+=""",
          """\sdpt=({dest_port}\d{1,100})""",
          """\sexternalId=({alert_id}\d{1,100})""",
          """\scs2=({additional_info}.+?)\s{0,100}\w+=""",
          """\sdvc=({host}[A-Fa-f:\d.]{1,2000})""",
          """\sdvchost=({host}[\w\-.]{1,2000})""",
          """\sduser=(N\/A|-|(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\\\/\s]{1,2000}?)))\s{0,100}\w+=""",
          """fname=({file_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
          """(mailUrlHash|fileHash)=({md5}.+?)\s{1,100}(\w+=|$)""",
          """\sact=({outcome}[^=]{1,2000}?)\s{0,100}\w+=""",
    
}
```