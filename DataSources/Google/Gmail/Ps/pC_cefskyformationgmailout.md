#### Parser Content
```Java
{
Name = cef-skyformation-gmail-out
  Vendor = Google
  Product = Gmail
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =Google Apps""", """act=send""", """dproc=Gmail""" ]
  Fields = [
     """"timestamp_usec":({time}\d{1,100})""",
     """\d\d\d\d-\d\d-\d\d-\d{1,100}:\w{3}\s\d\d\s\d\d:\d\d:\d\d\s{0,100}[^\s]{1,2000}\sSkyformation""", 
     """"destination":\[\{"address[":]{0,2000}({external_address}[^",]{1,2000})"""",
     """"destination":\[\{"address[":]{0,2000}({recipient}[^",]{1,2000})"""", 
     """"source":\{"address[":]{0,2000}({sender}[^",]{1,2000})""",
     """"subject":"({subject}[^"]{1,2000})"""",
     """act=({action}[^\s]{1,2000})""",
     """request=({outcome}[^\s]{1,2000})""",
     """deviceInboundInterface=({message_id}[^\s]{1,2000})""",
     """fsize=({bytes}\d{1,100})\s""",
     """"client_ip":"({dest_ip}[a-fA-F\d.:]{1,2000})"""",
     """requestClientApplication=({app}[^\s]{1,2000})""",
     """num_message_attachments":({num_attachments}\d{1,100})""",
     """fname=({file_name}[^\.]{1,2000}\.({file_ext}.*?))\s\w+=""",
  ]
  DupFields = ["sender->user_email"]
  

}
```