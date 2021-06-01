#### Parser Content
```Java
{
Name = symantec-file-write-5
  DataType = "file-write"
  Conditions = [ """"event_id":8004004""", """"type_id":8004""", """"Symantec Endpoint Detection and Response"""", """collector_device_ip""" ]
  Fields = ${SymantecParserTemplates.symantec-file-template.Fields}[
    """({file_type}directory)"""
  ]
}
symantec-file-template = {
    Vendor = Symantec
    Product = Symantec EDR
    Lms = Syslog
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """"(start_)?time":({time}\d{1,100})""",
      """collector_device_name":"({host}[^"]{1,2000})"""",
      """"path":"({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}?(\.({file_ext}[^\\\/\.;"]{1,2000}))?))"""",
      """user_name":"((?i)(LOCAL SERVICE|SYSTEM|NETWORK SERVICE)|({user}[^"]{1,2000}))"""",
      """user_domain":"(NT AUTHORITY|({domain}[^"]{1,2000}))"""",
      """"device_name":"({src_host}[^"]{1,2000})"""",
      """"message":"({additional_info}[^"]{1,2000})"""",
      """device_ip":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
      """src_ip":"({src_ip}[a-fA-F\d:.]{1,2000})""""
      """src_port":({src_port}\d{1,100})""",
      """dst_port":({dest_port}\d{1,100})""",
      """dst_ip":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
      """md5":"({md5}[^"]{1,2000})"""",
      """event_id":({event_code}\d{1,2000})""",
      """size":({file_size}\d{1,100})""",
      """cmd_line":"({command_line}[^\n]{1,2000}?)\s{0,100}","""
    ]  
  }
}
SymantecParsers = [

${SymantecParserTemplates.symantec-usb-activity}{
  Name = symantec-usb-read-1
  Conditions = [ """type":"""", ""","device":"""", """"action":"File Read"""" ]

```