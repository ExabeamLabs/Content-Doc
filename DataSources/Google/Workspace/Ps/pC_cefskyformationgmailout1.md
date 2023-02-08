#### Parser Content
```Java
{
Name = cef-skyformation-gmail-out-1
  Vendor = Google
  Product = Workspace
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """destinationServiceName =Google Apps""", """"service":"smtp-outbound"""", """dproc=Gmail Logs""", """"action_type":""" ]
  Fields = [
  """"timestamp_usec":({time}\d{1,100})""",
  """"destination":\[\{"address[":]{0,2000}({recipient}[^",]{1,2000})"""",
  """"source":\{"address[":]{0,2000}({sender}[^",]{1,2000})""",
  """"subject":"({subject}[^"]{1,2000})"""",
  """"selector":"({action}[^"]{1,2000})""",
  """"success":({outcome}true|false)""",
  """"rfc2822_message_id":"({message_id}[^"]{1,2000})"""",
  """"payload_size":({bytes}\d{1,20})""",
  """"client_ip":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
  """({app}Gmail|gmail)""",
  """num_message_attachments":({num_attachments}\d{1,100})"""
  ]
  DupFields = [ "sender->user_email" ]


}
```