#### Parser Content
```Java
{
Name = s-radius-wireless-nac-logon
  Vendor = Microsoft
  Product = Microsoft Radius
  Lms = Splunk
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """EventCode=6272""", """Message=Network Policy Server granted access to a user""" ]
  Fields = [
    """({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]+)""",
    """ComputerName=({host}[\w\-.]+)""",
    """EventCode=({event_code}\d+)""",
    """User:.+?Account Name:\s+(\w+(\\)+)?(?:-|({user}.+?))\s+Account Domain:""",
    """User:.+?Account Domain:\s+(?:-|({domain}.+?))\s+Fully""",
    """NAS Identifier:\s+(?:-|({location}[\w\-.]+))""",
    """Calling Station Identifier:\s+(?:-|({src_mac}.+?))\s+NAS:""",
    """Authentication Server:\s+(?:-|({auth_server}.+?))\s+Authentication Type:""",
    """User:.+?Fully Qualified Account Name:\s+(?:-|({user_type}.+?))(\/[^/\s]+)?\s+Client Machine:""",
    """NAS IPv4 Address:\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """NAS IPv6 Address:\s+({dest_ip}[a-fA-F:\d.]+)""",
    """EAP Type:\s+(?:-|({auth_type}.+?))\s+Account Session Identifier:""",
    """Result:\s+(?:-|({access_type}.+?))\s+Session Identifier:"""
  ]
}
```