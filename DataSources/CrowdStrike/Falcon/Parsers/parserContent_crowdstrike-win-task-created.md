#### Parser Content
```Java
{
Name = crowdstrike-win-task-created
  DataType = "windows-task-created"
  Conditions = [ """"event_simpleName":"ScheduledTaskRegistered""", """"event_platform":"Win""""]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"TaskName":"({task_name}[^"]+)"""
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
    """exabeam_host=({host}[\w.\-]+)""",
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