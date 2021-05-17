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
    """Timestamp"{1,20}:\s{1,100}"{1,20}({time}[^"]{1,2000})""",
    """Bit9Server"{1,20}:\s{1,100}"{1,20}({host}[^"]{1,2000})""",
    """EventType"{1,20}:\s{1,100}"{1,20}({alert_type}[^"]{1,2000})""",
    """EventSubType"{1,20}:\s{1,100}"{1,20}({alert_name}[^"]{1,2000})""",
    """HostName"{1,20}:\s{1,100}"{1,20}(({domain}[^\\]{1,2000})\\+)?({src_host}[^"]{1,2000})""",
    """HostIP"{1,20}:\s{1,100}"{1,20}({src_ip}[^"]{1,2000})""",
    """Priority"{1,20}:\s{1,100}"{1,20}({alert_severity}[^"]{1,2000})""",
    """ABId"{1,20}:\s{1,100}"{1,20}({alert_id}[^"]{1,2000})""",
    """Message"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]{1,2000})""",
    """PathName"{1,20}:\s{1,100}"{1,20}({malware_url}[^"]{1,2000})""",
    """UserName"{1,20}:\s{1,100}"{1,20}({user}[^"]{1,2000})""",
    """c:\\+users\\+({user}[^"\\]{1,2000})""",
  ]
}
```