#### Parser Content
```Java
{
Name = s-phantom-dlp-email-in
  Vendor = Phantom
  Product = Phantom
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """from: """, """,to: """, """,subject: """, """,analysed_time: """, """phantom""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """,analysed_time:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
    """from:\s*({sender}[^\s@,]+@[^\s@,]+)""",
    """,to:\s*({recipients}({recipient}[^\s@,;]+@({external_domain}[^\s@,;]+))[^,]*?)\s*,""",
    """,subject:\s*({subject}[^,]*?)\s*,""",
    """,severity:\s*({alert_severity}[^,]*?)\s*,""",
  ]
  DupFields = [ "recipient->user_email", "sender->external_address" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "recipient->dlpUser", "sender->emailFrom", "subject->emailSubject", "recipients->emailTo"]
    NameTemplate = """Phantom Phishing Email Alert ${subject} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="email", Fields=["recipient->email"]}
```