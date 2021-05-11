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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[\w\-.]+)?\s{0,100}(\(|\%)""",
    """SrcIP:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({web_domain}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """FileAction:\s{0,100}({action}[^,]+)""",
    """User:\s{0,100}(Unknown|({user}[^,\s]+))""",
    """Client:\s{0,100}({user_agent}[^,]+)""",
    """Protocol:\s{0,100}({protocol}[^,]+)""",
    """FileSize:\s{0,100}({bytes}[^,]+)""",
    """FilePolicy:\s{0,100}({policy}[^,]+?)\s{0,100}
```