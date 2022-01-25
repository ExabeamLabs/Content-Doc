#### Parser Content
```Java
{
Name = cef-O365-dlp-email-out-1
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ToAddress\\=""", """Subject\\=""", """type\\=EmailMessage""", """FromName\\=""", """FromAddress\\="""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wsuser=({sender}[^@]{1,2000}@({external_domain_sender}[^@\s]{1,2000}))""",
    """\Wcs2=({recipient}[^@]{1,2000}@({external_domain_recipient}[^@=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """ToAddress\\=({to_address}.+?)(;\w+\\=|\s{1,100}\w+=|\s{0,100}$)""",
    """CcAddress\\=(?:null|({cc_address}.+?))(;\w+\\=|\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=.*?"user-email":"({recipient}[^@"]{1,2000}@({external_domain_recipient}[^"]{1,2000}))""",
    """Subject\\=({subject}[^;]{1,2000}?)(\s{0,100}\[\s{0,100}ref:.*?\])?\s{0,100}(;|\s{1,100}\w+=|\s{1,100}$)""",
    """LastModifiedDate\\=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wact=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """Id\\=({alert_id}[^;\s]{1,2000})""",
    """({direction}o)"""
  ]
  DupFields = [ "sender->email_user", "sender->orig_user", "alert_name->alert_type", "recipient->external_address", "to_address->recipients" ]


}
```