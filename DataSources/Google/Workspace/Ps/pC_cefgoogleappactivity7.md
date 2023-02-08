#### Parser Content
```Java
{
Name = cef-google-app-activity-7
  Vendor = Google
  Product = Workspace
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """destinationServiceName =Google Apps""", """cat=audit""", """dproc=Gmail Logs""" ]
  Fields = [
  """"timestamp_usec":({time}\d{1,100})""",
  """"destination":\[\{"address[":]{0,2000}({recipient}[^",]{1,2000})"""",
  """"source":\{"address[":]{0,2000}({sender}[^",]{1,2000})""",
  """"subject":"({subject}[^"]{1,2000})"""",
  """"selector":"({activity}[^"]{1,2000})""",
  """"success":({outcome}true|false)""",
  """"rfc2822_message_id":"({message_id}[^"]{1,2000})"""",
  """"payload_size":({bytes}\d{1,20})""",
  """"client_ip":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
  """({app}Gmail|gmail)""",
  """"action_type":({action_type}\d{1,10})"""
  """"service":"({service}[^"]{1,200})"""
  """suser=(anonymous|({user}[^\s]{1,2000}))"""
  ]
  DupFields = [ "sender->user_email" ]


}
```