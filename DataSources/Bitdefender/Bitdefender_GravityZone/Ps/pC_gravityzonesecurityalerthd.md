#### Parser Content
```Java
{
Name = gravityzone-security-alert-hd
  Conditions = [ """gravityzone:""", """"module":"hd"""" ]

gravityzone-security-alert = {
    Vendor = Bitdefender
    Product = Bitdefender GravityZone
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"(timestamp|date|last_blocked)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"(attack_type|aph_type|exploit_type)":"({alert_type}[^"]{1,2000})""",
      """"user":\{[^\}]{0,2000}?"name":"(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))"""",
      """"computer_name":"({host}[^"]{1,2000})""",
      """"computer_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """"last_blocked":"({last_blocked_time}[^"]{1,2000})""",
      """"malware_name":"({alert_name}[^"]{1,2000})""",
      """"hash":"({md5}[^"]{1,2000})""",
      """"(file_path|exploit_path)":"({malware_file_name}[^"]{1,2000})""",
      """"status":"({outcome}[^"]{1,2000})""",
      """"final_status":"({outcome}[^"]{1,2000})""",
      """"malware_type":"({category}[^"]{1,2000})""",
      """"count":({count}\d{1,100})"""
    
}
```