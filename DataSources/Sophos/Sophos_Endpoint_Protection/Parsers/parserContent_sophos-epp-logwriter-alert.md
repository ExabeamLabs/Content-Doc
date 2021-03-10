#### Parser Content
```Java
{
Name = sophos-epp-logwriter-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ReportingName=""","""ComputerIPAddress=""" ]
  Fields = [
     """;\s+EventID=({alert_id}[\d]+);""",
     """;\s*EventTime=({time}[\d\- T\+:]+);""",
     """;\s*EventType=({alert_type}[^;]+);""",
     """;\s*Name=({alert_name}[^;]+);""",
     """;\s*UserName=([^\\]+\\+)?({user}[^;]+);""",
     """;\s*Action=({alert_severity}[^;]+);""",
     """;\s*({additional_info}SubType=[^;]+)""",
     """;\s*ComputerName=({src_host}[^;]+);""",
     """;\s*ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]+)""",
     """;\s*BlockedSite=({malware_url}[^;]+?)\s*(;|$)""",
     """;\s*Category=(|({alert_name}[^;]+?))\s*(;|$)""",
     """;\s*ReferringURL=({additional_info}[^;]+?)\s*(;|$)"""
  ]
}
```