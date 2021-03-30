#### Parser Content
```Java
{
Name = crowdstrike-modify-binary
  DataType = "file-operations"
  Conditions = [ """event_simpleName""", """ModifyServiceBinary""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"ServiceImagePath":"({file_path}({file_parent}[^"]*?\\+)({file_name}[^\\\s"]+?\.({file_ext}[^\\\s"\.]+?)))(\s|")"""
    """"ServiceObjectName":"({additional_info}[^"]+)"""
    """({accesses}Modify)"""
  ]
}
cef-crowdstrike-app-activity-temp = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """"timestamp":\s*"*({time}\d+)""",
    """"UserIp":\s*"({src_ip}[^"]+)""",
    """\WdestinationServiceName=({app}.+?)\s+\w+="""
    """({host}[\w\-.]+)\s+Skyformation""",
    """"event_simpleName":"({event_code}[^"]+)""",
    """"aid":"({aid}[^"]+)""",
    """"(ImageFileName|TargetFileName)":"({file_path}[^"]+)""",
    """"(ImageFileName|TargetFileName)":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))"""
    """"UserName":"({user}[^"]+?)""""
    """"aip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
    """"ClientComputerName":"({src_host}[^"]+)"""
  ]

```