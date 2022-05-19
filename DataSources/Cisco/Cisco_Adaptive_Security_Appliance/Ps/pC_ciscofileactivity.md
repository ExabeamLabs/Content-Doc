#### Parser Content
```Java
{
Name = cisco-file-activity
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """, ApplicationProtocol:""", """, FileDirection: """, """Client: """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[\w\-.]{1,2000})?\s{0,100}(\(|\%)""",
    """SrcIP:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({web_domain}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """FileAction:\s{0,100}({action}[^,]{1,2000})""",
    """User:\s{0,100}(Unknown|({user}[^,\s]{1,2000}))""",
    """Client:\s{0,100}({user_agent}[^,]{1,2000})""",
    """Protocol:\s{0,100}({protocol}[^,]{1,2000})""",
    """FileSize:\s{0,100}({bytes}[^,]{1,2000})""",
    """FilePolicy:\s{0,100}({policy}[^,]{1,2000}?)\s{0,100

}
```