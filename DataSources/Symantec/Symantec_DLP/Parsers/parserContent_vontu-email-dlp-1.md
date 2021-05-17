#### Parser Content
```Java
{
Name = vontu-email-dlp-1
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """Policy_Violated=""", """Protocol="SMTP"""", """Subject=""", """Blocked=""" ]
    Fields = [
      """(\w+ \d{1,100} \d\d:\d\d:\d\d)\s{1,100}({host}[^\s\.]{1,2000})\S* ID="({alert_id}\d{1,100})""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """\sPolicy_Violated="({alert_name}[^"]{1,2000})""",
      """\sProtocol="({protocol}[^"]{1,2000})""",
      """\sRecipient="({target}[^"]{0,2000})""",
      """\sSender="({user_email}[^"]{1,2000})""",
      """\sSeverity="({alert_severity}[^"]{1,2000})""",
      """\sSubject="({additional_info}[^"]{1,2000})""",
      """\sBlocked="({outcome}[^"]{1,2000})"""
    ]
    DupFields = [ "protocol->alert_type" ]
  }
```