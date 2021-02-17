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
    """\srt=({time}\d+)""",
    """({event_code}Send Mail)""",
    """\sshost=(([^\/\\=]+)[\/\\]+)?({host}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__EmailSender=({sender}[^\s@]+@[^\s@]+)""",
    """\sad\.DG__EmailRecipient=({external_address}[^\s@]+@({external_domain}[^\s@]+))""",
    """\sad\.DG__EmailSubject=({subject}.+?)\s+(ad\.\S+=|\w+=|$)""",
    """\ssuser=(({domain}[^\/\\=]+)[\/\\]+)?({user}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\sfname=\s*(?:message body|({file_name}[^=]+?))\s+(ad\.\S+=|\w+=|$)""",
  ]
  DupFields = [
    "file_name->attachment",
    "external_address->recipients",
    "user->email_user",
  ]
}
```