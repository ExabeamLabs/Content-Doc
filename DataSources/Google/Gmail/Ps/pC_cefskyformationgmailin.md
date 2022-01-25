#### Parser Content
```Java
{
Name = cef-skyformation-gmail-in
  Vendor = Google
  Product = Gmail
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =Google Apps""", """act=receive""", """dproc=Gmail""" ]
  Fields = [
    """"timestamp_usec":({time}\d{1,100})""",
    """\d\d\d\d-\d\d-\d\d-\d{1,100}:\w{3}\s\d\d\s\d\d:\d\d:\d\d\s{0,100}[^\s]{1,2000}\sSkyformation""", 
    """"subject":"({subject}[^"]{1,2000})"""",
    """"destination":\[\{"address[":]{0,2000}({recipient}[^",]{1,2000})"""",
    """"source":\{"address[":]{0,2000}({sender}[^",]{1,2000})""",
    """act=({action}[^\s]{1,2000})""",
    """request=({outcome}[^\s]{1,2000})""",   
    """deviceInboundInterface=({message_id}[^\s]{1,2000})""",
    """"payload_size":({bytes}\d{1,100})""",
    """"client_ip":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """requestClientApplication=({app}[^\s]{1,2000})""",
  ]
  DupFields = ["recipient->user_email", "sender->external_address"]


}
```