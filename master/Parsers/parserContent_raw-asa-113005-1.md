#### Parser Content
```Java
{
Name = raw-asa-113005-1
  Vendor = Cisco FPR
  Product = Cisco 
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ "-113005:", "AAA user authentication Rejected :", ": user =", ": reason =" ]
  Fields = [
    """({time}\d+\s+\w+\s+\d+\s+\d+:\d+:\d+)\s+UTC\s+({host}[^\s]+)\s+:\s+({event_code}[^\s]+):\s+({event_name}.+?)\s+:""",
    """reason\s+=\s+({failure_reason}.+?)\s+:"""
    """server\s+=\s+({dest_ip}.+?)\s+:"""
    """user\s+=\s+(\*+|({user}.+?))\s+:"""
    """user IP\s+=\s+({src_ip}[A-Za-z\d.:]+)"""
    ]
}


#splunk,rsasa,qradar
{
  Name = raw-asa-713228-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "Assigned private IP address", "-713228","""%ASA-""" ]
  Fields = [
    """exabeam_time=\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d+ (\d\d\d\d )?\d+:\d+:\d+):""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-:]+)""",
    """%ASA-({priority}\d+)-({event_code}\d+): Group =\s*({realm}[^,]+),\s*Username = ({user}[^,@]+?),?\s+IP = ({src_ip}[^\s,]+)[,\s]+Assigned private IP address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to"""
  ]
}
```