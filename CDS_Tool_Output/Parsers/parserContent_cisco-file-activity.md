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

{
  Name = cisco-adc-web-activity
  Vendor = Cisco
  Product = Cisco ADC
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """] """, """ [""", """[ADC_APP]""" ]
  Fields = [
    """\[({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\]\[\d+\]\[\S+\]\[\]\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s\[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d)\s+\+\d+\]\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s[\S]*\s\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s({dest_translated_port}\d+)?\s"({uri_path}\S+)"\s"({method}\S+)?\s\S*\s({protocol}\S+)?"\s"({full_url}\S+)?"\s"({user_agent}.*)?"""",
    """^([^\s]*\s){18}"(?:-|Mozilla\/.+?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}Chrome|Safari|Opera|(F|f)irefox|MSIE|Trident))""",
    """^([^\s]*\s){18}"(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """^([^\s]*\s){18}"(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
  ]
}
```