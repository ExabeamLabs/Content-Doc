#### Parser Content
```Java
{
Name = gravityzone-security-alert-aph-1
  Conditions = [ """CEF:""", """destinationServiceName =Custom Application""", """"module":"aph"""", """Bitdefender""" ]

gravityzone-security-alert = {
    Vendor = Bitdefender
    Product = GravityZone
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"(timestamp|date|last_blocked|created)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"(attack_type(s)?|aph_type|exploit_type)":\[?"({alert_type}[^"]{1,2000})""",
      """"user":\{[^\}]{0,2000}?"name":"(({user_email}[^"@]{1,2000}@[^"@\.]{1,2000}\.[^"]{1,2000})|({user}[^"@]{1,2000})(@({domain}[^@"\.]{1,2000}))?)"""",
      """"username":"(({domain}[^"\\]{1,2000})\\{1,20})?({user}[^\\"]{1,2000})"""",
      """"user_sid":"({user_sid}[^"]{1,2000})"""",
      """"computer_name":"({host}[^"]{1,2000})""",
      """"computer_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """"last_blocked":"({last_blocked_time}[^"]{1,2000})""",
      """"(detection_name|malware_name)":"({alert_name}[^"]{1,2000})""",
      """"hash":"({md5}[^"]{1,2000})""",
      """"(file_path|exploit_path)":"({malware_file_name}[^"]{1,2000})""",
      """"main_action":"({outcome}[^"]{1,2000})"""",
      """"status":"({outcome}[^"]{1,2000})""",
      """"final_status":"({outcome}[^"]{1,2000})""",
      """"malware_type":"({category}[^"]{1,2000})""",
      """"count":({count}\d{1,100})""",
      """"severity":"({alert_severity}[^"]{1,2000})"""",
      """"incident_id":"({alert_id}[^"]{1,2000})"""",
      """"process_command_line":"({command_line}[^$]{1,2000}?)","\w+""",
      """"process_path":"({process}({directory}[^"]{1,2000}?)[\\\/]{1,2000}({process_name}[^"\\\/]{1,2000}))"""",
      """"protocol_id":"({protocol}\d{1,5})""""
    ]
    DupFields = [ "directory -> process_directory" 
}
```