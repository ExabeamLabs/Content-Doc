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
     """SeverityValue":({alert_severity}\d+)""",
     """Category ID":"({alert_type}[^"]+)""",
     """Threat Name":"({category}[^"]+)""",
     """Domain":"({domain}[^"]+)""",
     """AccountName":"({account}[^"]+)""",
     """Detection User":"([^\\]+)\\*({user}[^"]+)""",
     """Detection ID":"\{*({alert_id}[^"\}]+)""",
     """Path":"(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))""",
     """"Path"\s*:\s*"({file_path}[^";]+)""",
     """"Path"\s*:\s*"(?:({file_parent}[^"]+?)\\+[^"\\;]+)""",
     """"Path"\s*:\s*"[^"]+\\({file_name}[^";,\s\&]+(\.({file_ext}[^"\\.;\s\&\-]+)))"""
     """UserID":"({user_sid}[^"]+)""",
     """Action Name":"({outcome}[^"]+)""",
     """Additional Actions String":"({additional_info}[^".]+)""",
     """Process Name":"(?:Unknown|({process}({directory}[^"]*?)(\\+({process_name}[^"\\]+?))?))"""",
     """Error Description":"({failure_reason}[^"]+)(\s*")+""",
     
  ]
}
{
  Name = raw-104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ 104 """, """Microsoft-Windows-Eventlog""", """log file was cleared.""" ]
  Fields = [
    """({host}\S+)\s+MSWinEventLog\s+\S+\s+\S+\s+\S+\s+\S+\s+({time}\w+ \d+ \d\d:\d\d:\d\d \d+)\s+({event_code}104)\s+Microsoft-Windows-Eventlog\s+(({domain}[^\\]+?)\\+)?({user}[^\s]+)"""
    """({event_name}The.*?log file was cleared.)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```