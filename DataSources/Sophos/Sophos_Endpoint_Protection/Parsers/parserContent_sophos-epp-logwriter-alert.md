#### Parser Content
```Java
{
Name = sophos-epp-logwriter-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """EventType=Virus""", """ReportingName=""","""ComputerIPAddress=""" ]
  Fields = [
     """;\s{1,100}EventID=({alert_id}[\d]{1,2000});""",
     """;\s{0,100}EventTime=({time}[\d\- T\+:]{1,2000});""",
     """;\s{0,100}EventType=({alert_type}[^;]{1,2000});""",
     """;\s{0,100}Name=({alert_name}[^;]{1,2000});""",
     """;\s{0,100}UserName=([^\\]{1,2000}\\+)?({user}[^;]{1,2000});""",
     """;\s{0,100}Action=({alert_severity}[^;]{1,2000});""",
     """;\s{0,100}({additional_info}SubType=[^;]{1,2000})""",
     """;\s{0,100}ComputerName=({src_host}[^;]{1,2000});""",
     """;\s{0,100}ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]{1,2000})""",
     """;\s{0,100}BlockedSite=({malware_url}[^;]{1,2000}?)\s{0,100}(;|$)""",
     """;\s{0,100}Category=(|({alert_name}[^;]{1,2000}?))\s{0,100}(;|$)""",
     """;\s{0,100}ReferringURL=({additional_info}[^;]{1,2000}?)\s{0,100}(;|$)"""
  ]
}
```