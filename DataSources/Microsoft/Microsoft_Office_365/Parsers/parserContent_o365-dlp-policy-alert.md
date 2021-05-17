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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"{0,20}CreationTime"{0,20}:\s{0,100}"{0,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"{0,20}""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]{1,2000})"""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}<?({object}[^"]{1,2000}?)>?"""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]{1,2000})"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"{0,20}""",
    """FileSize"{0,20}:\s{0,100}"{0,20}({bytes}\d{1,100})""",
    """From"{0,20}:\s{0,100}"{0,20}({sender}[^"]{1,2000})"""",
    """To"{0,20}:\s{0,100}\["{0,20}({recipient}[^"]{1,2000})""",
    """Subject"{0,20}:\s{0,100}"{0,20}({subject}[^"]{1,2000}?)\s{0,100}"""",
    """MessageID"{0,20}:\s{0,100}"{0,20}<?({message_id}[^"]{1,2000}?)>?"""",
    """Severity"{0,20}:\s{0,100}"{0,20}({alert_severity}[^"]{1,2000})"""",
    """IncidentId"{0,20}:\s{0,100}"{0,20}({alert_id}[^"]{1,2000})"""",
    """Actions"{0,20}:\s{0,100}\["{0,20}({outcome}[^"\]]{1,2000}?)\s{0,100}"""",
    """RuleName"{0,20}:\s{0,100}"{0,20}(|({alert_name}.+?[^"]))"""",
    """FileName"{0,20}:\s{0,100}"{0,20}(|({file_name}.+?[^"]))"""",
    """RecipientCount"{0,20}:\s{0,100}({recipient_count}\d{1,100})"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
```