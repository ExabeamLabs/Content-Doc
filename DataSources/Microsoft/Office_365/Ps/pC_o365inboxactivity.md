#### Parser Content
```Java
{
Name = o365-inbox-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName =Office 365""", """"ResultStatus"""" , """Add-MailboxPermission"""]
  Fields = [
     """exabeam_host=([^=]{1,2000}?@\s{0,100})?(gcs-topic|cc|({host}[\w.-]{1,2000}))""",
     """"CreationTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
     """flexString1=({activity}[^=]{0,2000}?)\s\w+=""",
     """\sby\s\[({user_email}[^@]{1,2000}@({email_domain}[^\]]{0,2000}))\]""",
     """ObjectId":"({resource}[^"]{0,2000})"""",
     """ResultStatus":"({outcome}[^"]{0,2000})"""",
     """Name":"AccessRights","Value":"({additional_info}[^"]{0,2000})"""",
     """destinationServiceName =(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
     """ClientIP":"\[?({src_ip}[^"\]]{0,2000})?\]?(:\d{5})""",
     """duser=([^=]{1,2000}\/)?({object}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
   ]


}
```