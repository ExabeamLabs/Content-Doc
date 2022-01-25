#### Parser Content
```Java
{
Name = crowdstrike-app-activity-4
  Conditions = [ """CEF:""", """|Skyformation|""", """"event_simpleName":"AwsEc2NetworkAcl"""" ]

crowdstrike-app-activity-temp = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """"timestamp":\s{0,100}"{0,20}({time}\d{1,100})""",
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