#### Parser Content
```Java
{
Name = code42-email-out-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss:SSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType":"EMAILED"""", """"osHostName""", """act=send""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"eventType"{1,20}:\s{0,100}"{1,20}({event_code}[^"]+)""",
    """"source":"{1,20}({log_source}[^"]+)"""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}[^"]+)"""",
    """"fileName"{1,20}:\s{0,100}"{1,20}({file_name}[^"]+?(\.({file_ext}[^\."]+))?)"""",
    """"fileCategory"{1,20}:\s{0,100}"{1,20}({file_type}[^"]+)"""",
    """"fileSize"{1,20}:\s{0,100}({bytes}\d{1,100})""",
    """"osHostName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]+)"""",
    """"eventType":"({alert_type}[^"]+)""",
    """"emailSender":"{1,20}({sender}[^"@]+@({external_domain_sender}[^"]+))"""",
    """"emailRecipients":\[*"{1,20}({recipient}[^"@]+@({external_domain_recipient}[^"]+))"""",
    """"emailSubject":\[*"{1,20}({subject}[^"]+)"""",
	
  ]
  DupFields = ["sender->email_user", "recipient->recipients" ]
}
```