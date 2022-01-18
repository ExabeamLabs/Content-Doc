#### Parser Content
```Java
{
Name = cef-digitalguardian-send-mail
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Digital Guardian|Digital Guardian|""", """|Send Mail|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """({event_code}Send Mail)""",
    """\sshost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({host}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__EmailSender=({sender}[^\s@]{1,2000}@[^\s@]{1,2000})""",
    """\sad\.DG__EmailRecipient=({external_address}[^\s@]{1,2000}@({external_domain}[^\s@]{1,2000}))""",
    """\sad\.DG__EmailSubject=({subject}.+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssuser=(({domain}[^\/\\=]{1,2000})[\/\\]{1,2000})?({user}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sfname=\s{0,100}(?:message body|({file_name}[^=]{1,2000}?))\s{1,100}(ad\.\S+=|\w+=|$)""",
  ]
  DupFields = [
    "file_name->attachment",
    "external_address->recipients",
    "user->email_user",
  ]


}
```