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
     """;\s{1,100}EventID=({alert_id}[\d]+);""",
     """;\s{0,100}EventTime=({time}[\d\- T\+:]+);""",
     """;\s{0,100}EventType=({alert_type}[^;]+);""",
     """;\s{0,100}Name=({alert_name}[^;]+);""",
     """;\s{0,100}UserName=([^\\]+\\+)?({user}[^;]+);""",
     """;\s{0,100}Action=({alert_severity}[^;]+);""",
     """;\s{0,100}({additional_info}SubType=[^;]+)""",
     """;\s{0,100}ComputerName=({src_host}[^;]+);""",
     """;\s{0,100}ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]+)""",
     """;\s{0,100}BlockedSite=({malware_url}[^;]+?)\s{0,100}(;|$)""",
     """;\s{0,100}Category=(|({alert_name}[^;]+?))\s{0,100}(;|$)""",
     """;\s{0,100}ReferringURL=({additional_info}[^;]+?)\s{0,100}(;|$)"""
  ]
}
```