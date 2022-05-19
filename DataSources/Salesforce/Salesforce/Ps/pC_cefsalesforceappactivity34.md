#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-34
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =Sales Cloud""", """type\=EmailMessage""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """LastModifiedDate\\=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
    """ValidatedFromAddress\\=({sender}[^@;]{1,2000}@({external_domain_sender}[^@\s;]{1,2000}));""",
    """Subject\\=({subject}[^;=]{1,2000});\w{1,100}\\=""",
    """ToAddress\\=({recipient}[^@;]{1,2000}@({external_domain_recipient}[^;\s]{1,2000}))""",
    """ToAddress\\=({recipients}[^=]{1,2000}?)\s{1,10}$""",
    """CcAddress\\=(?:null|({cc_address}[^;]{1,2000}?))(;\w{1,1000}\\=|\s{1,10}\w{1,1000}=|\s{0,10}$)"""
  ]
  DupFields = [ "sender->email_user", "sender->orig_user", "recipient->external_address", "recipients->to_address" ]


}
```