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
     """Hostname":"({host}[^"]+)""",
     """EventTime":"({time}[^"]+)""",
     """Category Name":"({alert_name}[^"]+)""",
     """SeverityValue":({alert_severity}\d{1,100})""",
     """Category ID":"({alert_type}[^"]+)""",
     """Threat Name":"({category}[^"]+)""",
     """Domain":"({domain}[^"]+)""",
     """AccountName":"({account}[^"]+)""",
     """Detection User":"([^\\]+)\\*({user}[^"]+)""",
     """Detection ID":"\{*({alert_id}[^"\}]+)""",
     """Path":"(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))""",
     """"Path"\s{0,100}:\s{0,100}"({file_path}[^";]+)""",
     """"Path"\s{0,100}:\s{0,100}"(?:({file_parent}[^"]+?)\\+[^"\\;]+)""",
     """"Path"\s{0,100}:\s{0,100}"[^"]+\\({file_name}[^";,\s\&]+(\.({file_ext}[^"\\.;\s\&\-]+)))"""
     """UserID":"({user_sid}[^"]+)""",
     """Action Name":"({outcome}[^"]+)""",
     """Additional Actions String":"({additional_info}[^".]+)""",
     """Process Name":"(?:Unknown|({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?))"""",
     """Error Description":"({failure_reason}[^"]+)(\s{0,100}")+""",
     
  ]
}
```