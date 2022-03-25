#### Parser Content
```Java
{
Name = json-sentinelone-threat-file-delete
  Product = Singularity
  DataType = "file-operations"
  Conditions = [ """"eventType": "File Deletion"""", """"agentName":""", """"fileFullName":""" ]
  Fields = ${SentinelOneParserTemplates.json-sentinelone-threat-events.Fields}[
    """"fileSha1":\s{0,10}"({sha1}[^"]{1,2000})"""" 
  ]

json-sentinelone-threat-events = {
    Vendor = SentinelOne
    Lms = ArcSight
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Fields = [ 
      """"timestamp":\s{0,10}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,10}Z)"""", 
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
      """"eventType":\s{0,10}"({event_name}[^"]{1,1000})"""",
      """"agentName":\s{0,10}"({dest_host}[^"]{1,1000})"""",
      """"fileFullName":\s{0,10}"({file_path}({file_parent}[^"]{1,2000}[\\\/]{1,2000})?({file_name}[^\\\/"]{1,2000}?(\.({file_ext}\w{1,100}))?))"""",
      """"processName":\s{0,10}"({process_name}[^"]{1,10})"""",
      """"dstIp":\s{0,10}"({dest_ip}[A-Fa-f:\d.]{1,10})"""",
      """"srcIp":\s{0,10}"({src_ip}[A-Fa-f:\d.]{1,10})"""",
      """"processUser":\s{0,100}"(({domain}[^"\\]{1,2000})\\{1,2})?({user}[^"]{1,2000})"""",
      """"agentDomain":\s{0,100}"({src_domain}[^"]{1,2000})""",
      """"agentComputerName":\s{0,100}"({src_host}[^"]{1,2000})"""
    
}
```