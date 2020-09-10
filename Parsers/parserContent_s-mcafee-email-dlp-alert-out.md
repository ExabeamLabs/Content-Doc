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
     """UserName="({domain}[^\\]+)\\({user}[^"]+)"""",
     """ComputerName="({src_host}[^"]+)"""",
     """EMAIL_RECIPIENT.+?>({recipient}[^<]+)<""",
     """EMAIL_SUBJECT.+?>({subject}[^<]+)<""",
     """FILE_NAME.+?>({attachment}[^<]+)<""",
     """FILE_NAME.+?size="({bytes}[^"]+)""",
     """UTCTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """Evidence="({recipients}[^=]+@[^,]+),""",
     """exabeam_host=({host}[^\s]+)"""
  ]
}
```