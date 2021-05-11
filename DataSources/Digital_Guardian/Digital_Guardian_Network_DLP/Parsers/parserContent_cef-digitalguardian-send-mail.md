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
    """\sshost=(([^\/\\=]+)[\/\\]+)?({host}[^=]+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__EmailSender=({sender}[^\s@]+@[^\s@]+)""",
    """\sad\.DG__EmailRecipient=({external_address}[^\s@]+@({external_domain}[^\s@]+))""",
    """\sad\.DG__EmailSubject=({subject}.+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssuser=(({domain}[^\/\\=]+)[\/\\]+)?({user}[^=]+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sfname=\s{0,100}(?:message body|({file_name}[^=]+?))\s{1,100}(ad\.\S+=|\w+=|$)""",
  ]
  DupFields = [
    "file_name->attachment",
    "external_address->recipients",
    "user->email_user",
  ]
}
```