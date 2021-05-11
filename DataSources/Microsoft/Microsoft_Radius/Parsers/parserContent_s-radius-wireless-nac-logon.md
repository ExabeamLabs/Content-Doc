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
    """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]+)""",
    """ComputerName=({host}[\w\-.]+)""",
    """EventCode=({event_code}\d{1,100})""",
    """User:.+?Account Name:\s{1,100}(\w+(\\)+)?(?:-|({user}.+?))\s{1,100}Account Domain:""",
    """User:.+?Account Domain:\s{1,100}(?:-|({domain}.+?))\s{1,100}Fully""",
    """NAS Identifier:\s{1,100}(?:-|({location}[\w\-.]+))""",
    """Calling Station Identifier:\s{1,100}(?:-|({src_mac}.+?))\s{1,100}NAS:""",
    """Authentication Server:\s{1,100}(?:-|({auth_server}.+?))\s{1,100}Authentication Type:""",
    """User:.+?Fully Qualified Account Name:\s{1,100}(?:-|({user_type}.+?))(\/[^/\s]+)?\s{1,100}Client Machine:""",
    """NAS IPv4 Address:\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """NAS IPv6 Address:\s{1,100}({dest_ip}[a-fA-F:\d.]+)""",
    """EAP Type:\s{1,100}(?:-|({auth_type}.+?))\s{1,100}Account Session Identifier:""",
    """Result:\s{1,100}(?:-|({access_type}.+?))\s{1,100}Session Identifier:"""
  ]
}
```