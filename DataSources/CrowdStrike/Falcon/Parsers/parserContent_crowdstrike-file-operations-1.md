#### Parser Content
```Java
{
Name = crowdstrike-file-operations-1
  DataType = "file-operations"
  Conditions = [ """"event_simpleName":"File""", """Info"""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)""""
  """"name":"({alert_name}[^"]+?)""""
  """"File({accesses}Delete|Open|Rename)"""
  ]
}
cef-crowdstrike-app-activity-temp = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """"timestamp":\s{0,100}"{0,20}({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """"UserIp":\s{0,100}"({src_ip}[^"]+)""",
    """\WdestinationServiceName=({app}.+?)\s{1,100}\w+="""
    """"event_simpleName":"({event_code}[^"]+)""",
    """"aid":"({aid}[^"]+)""",
    """"(ImageFileName|TargetFileName)":"({file_path}[^"]+)""",
    """"(ImageFileName|TargetFileName)":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))"""
    """"UserName":"({user}[^"]+?)""""
    """"aip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
    """"ClientComputerName":"({src_host}[^"]+)"""
  ]

```