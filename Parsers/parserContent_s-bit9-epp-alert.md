#### Parser Content
```Java
{
Name = s-bit9-epp-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """"Bit9Server"""", """"ProcessHashType"""" ]
  Fields = [
    """Timestamp"+:\s+"+({time}[^"]+)""",
    """Bit9Server"+:\s+"+({host}[^"]+)""",
    """EventType"+:\s+"+({alert_type}[^"]+)""",
    """EventSubType"+:\s+"+({alert_name}[^"]+)""",
    """HostName"+:\s+"+(({domain}[^\\]+)\\+)?({src_host}[^"]+)""",
    """HostIP"+:\s+"+({src_ip}[^"]+)""",
    """Priority"+:\s+"+({alert_severity}[^"]+)""",
    """ABId"+:\s+"+({alert_id}[^"]+)""",
    """Message"+:\s+"+({additional_info}[^"]+)""",
    """PathName"+:\s+"+({malware_url}[^"]+)""",
    """UserName"+:\s+"+({user}[^"]+)""",
    """c:\\+users\\+({user}[^"\\]+)""",
  ]
}
```