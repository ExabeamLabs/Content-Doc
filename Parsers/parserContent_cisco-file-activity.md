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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)?\s*(\(|\%)""",
    """SrcIP:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s*({web_domain}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """SrcPort:\s*({src_port}\d+)""",
    """DstPort:\s*({dest_port}\d+)""",
    """FileAction:\s*({action}[^,]+)""",
    """User:\s*(Unknown|({user}[^,\s]+))""",
    """Client:\s*({user_agent}[^,]+)""",
    """Protocol:\s*({protocol}[^,]+)""",
    """FileSize:\s*({bytes}[^,]+)""",
    """FilePolicy:\s*({policy}[^,]+?)\s*,""",
    """FileDirection:\s*({direction}[^,]+)""",
    """FileName:\s*(|({file_path}(|({file_parent}[^",]*?))[\\\/]*({file_name}[^\\\/",]+?(\.({file_ext}[^\\\/\.\s",]+))?)))\s*,""",
  ]
}
```