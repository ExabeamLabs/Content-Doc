#### Parser Content
```Java
{
Name = json-exchange-scanmail-alert
  Vendor = Microsoft
  Product = Microsoft ScanMail
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """has been detected""", """has been taken on""", """Message details:""" ]
  Fields = [
    """(|({alert_name}[^"]+?))\s+has been detected,and\s+(|({outcome}.+?))\s+has been taken on\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(PM|AM|pm|am)).\\nMessage details:\\nServer:\s*(|({host}[\w.\-]+))\\nFound in:\s*(|({alert_type}.+?))\\nSender:\s*(|({malware_url}.+?));\\nRecipient:\s*(|({user_email}.+?));\\nSubject:\s*(|({additional_info}.+?))\s*\\nAttachment name:\s*(|({file_name}[^"]+?))("|\s*$)""",
   """"hostname":"({src_host}[^"]+)""", 
   """"level":"({alert_severity}[^"]+)""", 
  ]
}
```