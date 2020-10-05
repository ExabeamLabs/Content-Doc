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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventTimestamp"+:\s*"+({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """"eventType"+:\s*"+({event_code}[^"]+)""",
    """"source":"+({log_source}[^"]+)"""",
    """"eventTimestamp"+:\s*"+({time}[^"]+)"""",
    """"fileName"+:\s*"+({file_name}[^"]+?(\.({file_ext}[^\."]+))?)"""",
    """"fileCategory"+:\s*"+({file_type}[^"]+)"""",
    """"fileSize"+:\s*({bytes}\d+)""",
    """"osHostName"+:\s*"+({dest_host}[^"]+)"""",
    """"eventType":"({alert_type}[^"]+)""",
    """"emailSender":"+({sender}[^"@]+@({external_domain_sender}[^"]+))"""",
    """"emailRecipients":\[*"+({recipient}[^"@]+@({external_domain_recipient}[^"]+))"""",
    """"emailSubject":\[*"+({subject}[^"]+)"""",
	
  ]
  DupFields = ["sender->email_user", "recipient->recipients" ]
}
```