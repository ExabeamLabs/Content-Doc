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
      """(\w+ \d{1,100} \d\d:\d\d:\d\d)\s{1,100}({host}[^\s\.]+)\S* ID="({alert_id}\d{1,100})""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """\sPolicy_Violated="({alert_name}[^"]+)""",
      """\sProtocol="({protocol}[^"]+)""",
      """\sRecipient="({target}[^"]*)""",
      """\sSender="({user_email}[^"]+)""",
      """\sSeverity="({alert_severity}[^"]+)""",
      """\sSubject="({additional_info}[^"]+)""",
      """\sBlocked="({outcome}[^"]+)"""
    ]
    DupFields = [ "protocol->alert_type" ]
  }
```