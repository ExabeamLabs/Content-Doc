#### Parser Content
```Java
{
Name = crowdstrike-usb-alert
  DataType = "dlp-alert"
  Conditions = [ """"event_simpleName":"DcUsbDevicePolicyViolation"""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]{1,2000}?)""""
  """"name":"({alert_name}[^"]{1,2000}?)""""
  """"DeviceProduct":"\s{0,100}(\s{1,20}|({additional_info}[^"]{1,2000}?))\s{0,100}""""
  """"DeviceInstanceId":"({target}[^"]{1,2000})""",
  """"event_simpleName":"({alert_type}[^"]{1,2000})""",
  
  ]

cef-crowdstrike-app-activity-temp = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """"timestamp":\s{0,100}"{0,20}({time}\d{1,100})"""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"UserIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)\s{1,100}\w+="""
    """"event_simpleName":"({event_code}[^"]{1,2000})""",
    """"aid":"({aid}[^"]{1,2000})""",
    """"(ImageFileName|TargetFileName)":"({file_path}[^"]{1,2000})""",
    """"(ImageFileName|TargetFileName)":"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000}\.({file_ext}[^\\\/"]{1,2000}))"""
    """"UserName":"({user}[^"]{1,2000}?)""""
    """"aip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
    """"ClientComputerName":"({src_host}[^"]{1,2000})"""
  
}
```