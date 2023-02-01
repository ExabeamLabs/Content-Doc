#### Parser Content
```Java
{
Name = symantec-file-alert
  DataType = "file-alert"
  Conditions = [ """"event_id":8031004""", """"type_id":8031""", """"Symantec Endpoint Detection and Response"""", """collector_device_ip""" ]
  Fields = ${SymantecParserTemplates.symantec-file-template.Fields}[
    """message":"({alert_name}Suspicious file)"""
  ]

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
  },

  symantec-app-template = {
    Vendor = Symantec
    Product = Symantec EDR
    Lms = Syslog
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """\\"time\\":\\"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """\\"message\\":\\"({additional_info}[^"\\]{1,2000})""",
      """\\"user_name\\":\\"({user}[^\\"]{1,2000})""",
      """\\"event_id\\":({event_code}\d{1,10})""",
      """\\"user_uid\\":\\"({uuid}[^\\"]{1,2000})""",
      """\\"destinationServiceName\\":\\"({app}[^\\"]{1,2000})""",
      """\\"session_uid\\":\\"({session_id}[^\\"]{1,2000})""",
      """\\"ipv4\\":\\"({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """\\"device_os_name\\":\\"({os}[^"\\]{1,2000})""",
      """\\"device_name\\":\\"({host}[\w\-.]{1,2000})""",
      """\\"device_domain\\":\\"({domain}[^"\\]{1,2000})"""
    
}
```