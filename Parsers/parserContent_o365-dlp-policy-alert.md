#### Parser Content
```Java
{
Name = o365-dlp-policy-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """"RuleName"""", """"PolicyDetails"""", """Operation""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """Workload"*:\s*"*({app}[^"]+)"""",
    """ObjectId"*:\s*"*<?({object}[^"]+?)>?"""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserId"*:\s*"*({user_email}[^@]+@({email_domain}[^"]+))"*""",
    """FileSize"*:\s*"*({bytes}\d+)""",
    """From"*:\s*"*({sender}[^"]+)"""",
    """To"*:\s*\["*({recipient}[^"]+)""",
    """Subject"*:\s*"*({subject}[^"]+?)\s*"""",
    """MessageID"*:\s*"*<?({message_id}[^"]+?)>?"""",
    """Severity"*:\s*"*({alert_severity}[^"]+)"""",
    """IncidentId"*:\s*"*({alert_id}[^"]+)"""",
    """Actions"*:\s*\["*({outcome}[^"\]]+?)\s*"""",
    """RuleName"*:\s*"*(|({alert_name}.+?[^"]))"""",
    """FileName"*:\s*"*(|({file_name}.+?[^"]))"""",
    """RecipientCount"*:\s*({recipient_count}\d+)"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
```