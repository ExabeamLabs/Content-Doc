#### Parser Content
```Java
{
Name = s-mcafee-email-dlp-alert-out
  Vendor = McAfee
  Product = McAfee Email Protection
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """OUTGOING_EMAIL""", """DLP: Email Protection""" ]
  Fields = [
     """UserName="({domain}[^\\]{1,2000})\\({user}[^"]{1,2000})"""",
     """ComputerName="({src_host}[^"]{1,2000})"""",
     """EMAIL_RECIPIENT.+?>({recipient}[^<]{1,2000})<""",
     """EMAIL_SUBJECT.+?>({subject}[^<]{1,2000})<""",
     """FILE_NAME.+?>({attachment}[^<]{1,2000})<""",
     """FILE_NAME.+?size="({bytes}[^"]{1,2000})""",
     """UTCTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """Evidence="({recipients}[^=]{1,2000}@[^,]{1,2000}),""",
     """exabeam_host=({host}[^\s]{1,2000})"""
  ]
}
```