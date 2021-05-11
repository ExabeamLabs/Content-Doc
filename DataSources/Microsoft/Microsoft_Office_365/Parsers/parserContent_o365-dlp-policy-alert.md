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
    """"{0,20}CreationTime"{0,20}:\s{0,100}"{0,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"{0,20}""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]+)"""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}<?({object}[^"]+?)>?"""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]+)"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@]+@({email_domain}[^"]+))"{0,20}""",
    """FileSize"{0,20}:\s{0,100}"{0,20}({bytes}\d{1,100})""",
    """From"{0,20}:\s{0,100}"{0,20}({sender}[^"]+)"""",
    """To"{0,20}:\s{0,100}\["{0,20}({recipient}[^"]+)""",
    """Subject"{0,20}:\s{0,100}"{0,20}({subject}[^"]+?)\s{0,100}"""",
    """MessageID"{0,20}:\s{0,100}"{0,20}<?({message_id}[^"]+?)>?"""",
    """Severity"{0,20}:\s{0,100}"{0,20}({alert_severity}[^"]+)"""",
    """IncidentId"{0,20}:\s{0,100}"{0,20}({alert_id}[^"]+)"""",
    """Actions"{0,20}:\s{0,100}\["{0,20}({outcome}[^"\]]+?)\s{0,100}"""",
    """RuleName"{0,20}:\s{0,100}"{0,20}(|({alert_name}.+?[^"]))"""",
    """FileName"{0,20}:\s{0,100}"{0,20}(|({file_name}.+?[^"]))"""",
    """RecipientCount"{0,20}:\s{0,100}({recipient_count}\d{1,100})"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
```