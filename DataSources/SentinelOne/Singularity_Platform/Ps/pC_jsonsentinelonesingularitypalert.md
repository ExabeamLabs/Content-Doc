#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-alert
  Product = Singularity Platform
  Vendor = SentinelOne
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Lms = Direct
  DataType = "alert"
  Conditions = [ """"dataSource.name":"SentinelOne"""", """"event.category":"ip"""", """"event.type":"IP Connect""""]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""
    """"dst.ip.address":"({src_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({dest_port}\d+))?"""
    """"src.ip.address":"({dest_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({dest_port}\d+))?"""
    """"src.port.number":\s*({src_port}\d{1,100})"""
    """"dst.port.number":\s*({dest_port}\d{1,100})"""
    """"event\.type":"({alert_name}[^"]{1,2000})"""
    """"event\.category":"({alert_type}[^"]{1,2000})"""",
    """"endpoint\.name":"({dest_host}[^"]{1,2000})"""
    """process\.name":"({process_name}[^"]{1,2000})""",
    """"endpoint.os":"({os}[^"]{1,2000})"""
    """"agent.version":\s*"+({user_agent}[^"]{1,2000})""""
    """"src.process.user":"*((NT AUTHORITY|({domain}[^\\"]{1,2000}))[\\\/]{1,2000})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))"""
    """"src.process.image.sha256":\s*\\?"{1,100}({hash_sha256}[^"\\]{1,2000})"""
    """"src.process.image.sha1":\s*\\?"{1,100}({hash_sha1}[^"\\]{1,2000})"""
    """"src.process.image.md5":\s*\\?"{1,100}({hash_md5}[^"\\]{1,2000})"""
    """"src.process.pid":\s*({process_id}\d{1,100})"""
    """"src.process.image.path":"({process_path}({process_directory}[^"]{1,2000}?)[\\\/]{1,2000}({process_name}[^"\\\/]{1,2000}))\\{1,2000}""""
  ]


}
```