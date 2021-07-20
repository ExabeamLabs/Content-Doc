#### Parser Content
```Java
{
Name = cef-windows-defender
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""Microsoft-Windows-Windows Defender/Operational""" , """Severity ID"""]
  Fields =[
     """Hostname":"({host}[^"]{1,2000})""",
     """EventTime":"({time}[^"]{1,2000})""",
     """Category Name":"({alert_name}[^"]{1,2000})""",
     """SeverityValue":({alert_severity}\d{1,100})""",
     """Category ID":"({alert_type}[^"]{1,2000})""",
     """Threat Name":"({category}[^"]{1,2000})""",
     """Domain":"({domain}[^"]{1,2000})""",
     """AccountName":"({account}[^"]{1,2000})""",
     """Detection User":"([^\\]{1,2000})\\*({user}[^"]{1,2000})""",
     """Detection ID":"\{*({alert_id}[^"\}]{1,2000})""",
     """Path":"(\w+:_)?({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}?(\.({file_ext}[^\\\/\.;"]{1,2000}))))""",
     """"Path"\s{0,100}:\s{0,100}"({file_path}[^";]{1,2000})""",
     """"Path"\s{0,100}:\s{0,100}"(?:({file_parent}[^"]{1,2000}?)\\+[^"\\;]{1,2000})""",
     """"Path"\s{0,100}:\s{0,100}"[^"]{1,2000}\\({file_name}[^";,\s\&]{1,2000}(\.({file_ext}[^"\\.;\s\&\-]{1,2000})))"""
     """UserID":"({user_sid}[^"]{1,2000})""",
     """Action Name":"({outcome}[^"]{1,2000})""",
     """Additional Actions String":"({additional_info}[^".]{1,2000})""",
     """Process Name":"(?:Unknown|({process}({directory}[^"]{0,2000}?)(\\+({process_name}[^"\\]{1,2000}?))?))"""",
     """Error Description":"({failure_reason}[^"]{1,2000})(\s{0,100}")+""",
     
  ]
}
```