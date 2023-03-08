#### Parser Content
```Java
{
Name = vontu-email-dlp-2
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "MMMM dd, yyyy HH:mm:ss a"
  Conditions = [ """Policy_Violated:_""", """Subject:_""", """Email_Blocked:""", """Sender:_""", """Attachment:_""" ]
  Fields = [
    """Incident_Date:\_({time}\w{1,10}\s\d\d,\s\d\d\d\d\s\d{1,2}:\d{1,2}:\d{1,2}\s((?i)am|pm))"""
    """\s\d\d\s\d\d:\d\d:\d\d\s({host}[\w\.\-]{1,2000})\s""",
    """\sEmail_Blocked:\_({outcome}[^\s,]{1,2000})""",
    """\sSender:\_({sender}[^\s@:]{1,2000}@[^\s\.:]{1,2000}\.[^\s:]{1,2000})""",
    """\sRecipient:\_({recipients}({recipient}[^\s@:,]{1,2000}@[^\s\.:,]{1,2000}\.[^\s:,]{1,2000})[^:]{0,2000}?)\sSubject:""",
    """Subject:\_(N\/A|({subject}[^\n]{1,2000}?))\s{0,20}Attachment:""",
    """Policy_Violated:\_({alert_type}[^:]{1,2000}?)(\s\-\s|\sSender:)""",
    """({alert_name}Policy_Violated)""",
    """Attachment:\_(N\/A|Unknown|({attachment}[^\n]{1,2000}?\.\w{1,20}?))\s""",
    """Attachment:\_(N\/A|Unknown|({attachments}[^\n]{1,2000}?))\s{1,20}Incident_Link:""",
    """Message_ID:\_({alert_id}[^\s]{1,2000})"""
  ]
  DupFields = ["alert_id->message_id"]


}
```