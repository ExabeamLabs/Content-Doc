#### Parser Content
```Java
{
Name = json-sentinelone-registry-write-7
DataType = "registry-write"
Lms = Direct
Conditions = [ """"dataSource.name\":\"SentinelOne\"""", """"event.category\":\"registry\"""", """"event.type\":\"Registry Key Security Changed\""""]

json-sentinelone-singularityp-events = {
    Product = Singularity 
    Vendor = SentinelOne
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"timestamp\\{0,20}":\\{0,20}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\\{0,20}"""",
      """"event\.type\\{0,20}":\\{0,20}"({alert_name}[^"]{1,2000}?)\\{0,20}"""",
      """"event\.category\\{0,20}":\\{0,20}"({alert_type}[^"]{1,2000}?)\\{0,20}"""",
      """process\.name\\{0,20}":\\{0,20}"({process_name}[^"]{1,2000}?)\\{0,20}"""",
      """"endpoint.os\\{0,20}":\\{0,20}"({os}[^"]{1,2000}?)\\{0,20}"""",
      """"agent.version\\{0,20}":\\{0,20}"({user_agent}[^"]{1,2000}?)\\{0,20}"""",
      """"src.process.user\\{0,20}":\\{0,20}"((NT AUTHORITY|({domain}[^\\"]{1,2000}))[\\\/]{1,2000})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))""",
      """"src.process.image.sha256\\{0,20}":\\{0,20}"({sha256}[^"]{1,2000}?)\\{0,20}"""",
      """"src.process.image.sha1\\{0,20}":\\{0,20}"({sha1}[^"]{1,2000}?)\\{0,20}"""",
      """"src.process.image.md5\\{0,20}":\\{0,20}"({md5}[^"]{1,2000}?)\\{0,20}"""",
      """"src.process.pid":({pid}\d{1,100})""",
      """"src.process.image.path\\{0,20}":\\{0,20}"{1,10}({process}({process_directory}[^"]{1,2000}?)\\{1,20}({process_name}[^"\\]{1,2000}))\\{0,20}"""",
      """"registry.keyPath\\{0,20}":\\{0,20}"({object}({registry_path}({registry_key}[^"]{1,2000}?)\\{1,20}({registry_value}[^"\\]{1,2000})))\\{0,20}""""
    
}
```