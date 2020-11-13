#### Parser Content
```Java
{
Name = symantec-epp-alert-chinese
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,实际的操作:""",""",请求的操作:""" ]
  Fields = [
         """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
         """exabeam_host=({host}\S+)""",
         """计算机名:\s*(?:0+|({host}[^,]+))""",
         """事件时间:\s*({time}[\d\- :]+)""",
         """({alert_type}(发现病毒|发现安全风险))""",
         """IP 地址:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """风险名称:\s*({alert_name}[^,]+)""",
         """出现次数:\s*\d+,({malware_url}[^,]+)""",
         """用户:\s*({user}[^,]+)""",
         """计算机名:\s*(?:0+|({src_host}[^,]+))""",
         """源计算机:\s*(?:0+|({dest_host}[^,]+))?,""",
         """源 IP:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """可信度:\s*({additional_info}[^,]+)\s*"""
        ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```