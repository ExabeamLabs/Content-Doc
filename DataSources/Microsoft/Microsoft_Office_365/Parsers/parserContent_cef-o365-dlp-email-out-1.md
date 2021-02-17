#### Parser Content
```Java
{
Name = cef-O365-dlp-email-out-1
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """|resource-event|""", """msg=EmailMessage send by User email""", """act=send""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wsuser=({sender}[^@]+@({external_domain_sender}[^@\s]+))""",
    """\Wcs2=({recipient}[^@]+@({external_domain_recipient}[^@=]+?))\s+(\w+=|$)""",
    """ToAddress\\=({to_address}.+?)(;\w+\\=|\s+\w+=|\s*$)""",
    """CcAddress\\=(?:null|({cc_address}.+?))(;\w+\\=|\s+\w+=|\s*$)""",
    """\Wcs2=.*?"user-email":"({recipient}[^@"]+@({external_domain_recipient}[^"]+))""",
    """Subject\\=({subject}[^;]+?)(\s*\[\s*ref:.*?\])?\s*(;|\s+\w+=|\s+$)""",
    """LastModifiedDate\\=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)""",
    """\Wact=({alert_name}.+?)\s+(\w+=|$)""",
    """Id\\=({alert_id}[^;\s]+)""",
    """({direction}o)"""
  ]
  DupFields = [ "sender->email_user", "sender->orig_user", "alert_name->alert_type", "recipient->external_address", "to_address->recipients" ]
}
```