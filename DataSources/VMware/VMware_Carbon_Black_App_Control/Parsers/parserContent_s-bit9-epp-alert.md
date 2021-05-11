#### Parser Content
```Java
{
Name = s-bit9-epp-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """"Bit9Server"""", """"ProcessHashType"""" ]
  Fields = [
    """Timestamp"{1,20}:\s{1,100}"{1,20}({time}[^"]+)""",
    """Bit9Server"{1,20}:\s{1,100}"{1,20}({host}[^"]+)""",
    """EventType"{1,20}:\s{1,100}"{1,20}({alert_type}[^"]+)""",
    """EventSubType"{1,20}:\s{1,100}"{1,20}({alert_name}[^"]+)""",
    """HostName"{1,20}:\s{1,100}"{1,20}(({domain}[^\\]+)\\+)?({src_host}[^"]+)""",
    """HostIP"{1,20}:\s{1,100}"{1,20}({src_ip}[^"]+)""",
    """Priority"{1,20}:\s{1,100}"{1,20}({alert_severity}[^"]+)""",
    """ABId"{1,20}:\s{1,100}"{1,20}({alert_id}[^"]+)""",
    """Message"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]+)""",
    """PathName"{1,20}:\s{1,100}"{1,20}({malware_url}[^"]+)""",
    """UserName"{1,20}:\s{1,100}"{1,20}({user}[^"]+)""",
    """c:\\+users\\+({user}[^"\\]+)""",
  ]
}
```