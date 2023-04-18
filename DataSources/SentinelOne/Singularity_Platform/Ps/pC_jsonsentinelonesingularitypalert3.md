#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-alert-3
  Product = Singularity Platform
  Vendor = SentinelOne
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Lms = Direct
  DataType = "alert"
  Conditions = [ """"dataSource.name\":\"SentinelOne\"""", """"event.category\":\"ip\"""", """"event.type\":\"IP Connect\""""]
  Fields = [
    """"timestamp\\{0,20}":\\{0,20}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""
    """"dst.ip.address\\{0,20}":\\{0,20}"({src_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({dest_port}\d+))?"""
    """"src.ip.address\\{0,20}":\\{0,20}"({dest_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({dest_port}\d+))?"""
    """"src.port.number\\{0,20}":\s*({src_port}\d{1,100})"""
    """"dst.port.number\\{0,20}":\s*({dest_port}\d{1,100})"""
    """"event\.type\\{0,20}":\\{0,20}"({alert_name}[^"\\]{1,2000})"""
    """"event\.category\\{0,20}":\\{0,20}"({alert_type}[^"]{1,2000}?)\\{0,20}"""",
    """"endpoint\.name\\{0,20}":\\{0,20}"({dest_host}[^"\\]{1,2000})"""
    """process\.name\\{0,20}":\\{0,20}"({process_name}[^"\\]{1,2000})""",
    """"endpoint.os\\{0,20}":\\{0,20}"({os}[^"\\]{1,2000})"""
    """"agent.version\\{0,20}":\s*\\{0,20}"+({user_agent}[^"]{1,2000}?)\\{0,20}""""
    """"src.process.user\\{0,20}":\\{0,20}"*((NT AUTHORITY|({domain}[^\\"]{1,2000}))[\\\/]{1,2000})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))"""
    """"src.process.image.sha256\\{0,20}":\s*\\{0,20}"{1,100}({hash_sha256}[^"\\]{1,2000})"""
    """"src.process.image.sha1\\{0,20}":\s*\\{0,20}"{1,100}({hash_sha1}[^"\\]{1,2000})"""
    """"src.process.image.md5\\{0,20}":\s*\\{0,20}"{1,100}({hash_md5}[^"\\]{1,2000})"""
    """"src.process.pid\\{0,20}":\s*({process_id}\d{1,100})"""
    """"src.process.image.path\\{0,20}":\\{0,20}"({process_path}({process_directory}[^"]{1,2000}?)[\\\/]{1,2000}({process_name}[^"\\\/]{1,2000}))\\{0,20}""""
  ]


}
```