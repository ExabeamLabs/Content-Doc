#### Parser Content
```Java
{
Name = json-exchange-scanmail-alert
  Vendor = Microsoft
  Product = ScanMail
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """has been detected""", """has been taken on""", """Message details:""" ]
  Fields = [
    """(|({alert_name}[^"]{1,2000}?))\s{1,100}has been detected,and\s{1,100}(|({outcome}.+?))\s{1,100}has been taken on\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(PM|AM|pm|am)).\\nMessage details:\\nServer:\s{0,100}(|({host}[\w.\-]{1,2000}))\\nFound in:\s{0,100}(|({alert_type}.+?))\\nSender:\s{0,100}(|({malware_url}.+?));\\nRecipient:\s{0,100}(|({user_email}.+?));\\nSubject:\s{0,100}(|({additional_info}.+?))\s{0,100}\\nAttachment name:\s{0,100}(|({file_name}[^"]{1,2000}?))("|\s{0,100}$)""",
   """"hostname":"({src_host}[^"]{1,2000})""", 
   """"level":"({alert_severity}[^"]{1,2000})""", 
  ]


}
```