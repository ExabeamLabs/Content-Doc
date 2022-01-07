#### Parser Content
```Java
{
Name = cef-skyformation-gmail-in
  Vendor = Google
  Product = Workspace
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =Google Apps""", """"service":"smtp-inbound"""", """dproc=Gmail""" ]
  Fields = [
    """"timestamp_usec":({time}\d{1,100})""",
    """"subject":"({subject}[^"]{1,2000})"""",
    """"destination":\[\{"address[":]{0,2000}({recipient}[^",]{1,2000})"""",
    """"source":\{"address[":]{0,2000}({sender}[^",]{1,2000})""",
    """"service":"({action}[^"]{1,2000})""",
    """"success":({outcome}true|false)""",
    """"rfc2822_message_id"{1,200}:"{1,20}({message_id}[^"]{1,2000})""",
    """"payload_size":({bytes}\d{1,100})""",
    """"client_ip":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """\sdestinationServiceName =({app}[^=]{1,2000}?)\s{0,20}\w+="""
  ]
  DupFields = ["recipient->user_email", "sender->external_address"]


}
```