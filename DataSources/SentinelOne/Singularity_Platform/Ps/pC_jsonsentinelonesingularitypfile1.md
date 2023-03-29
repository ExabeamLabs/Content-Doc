#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-file-1
  Lms = Direct
  DataType = "file-operations"
  Conditions = [ """"dataSource.name\":\"SentinelOne\"""", """"i.scheme\":\"edr\"""", """"event.category\":\"file\"""", """"event.type\":""" ]

json-sentinelone-edr-events = {
    Vendor = SentinelOne
    Product = "Singularity Platform"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"timestamp\\{0,20}":\\{0,20}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\\{0,20}"""",
      """"event\.type\\{0,20}":\\{0,20}"({event_name}[^"\\]{1,2000})""",
      """"endpoint\.name\\{0,20}":\\{0,20}"({dest_host}[^"\\]{1,2000})""",
      """"task\.path\\{0,20}":\\{0,20}"({file_path}({file_dir}[^"]{0,2000}?)({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\\."]{1,2000}?))?))\\{0,20}"""",
      """process\.name\\{0,20}":\\{0,20}"({process_name}[^"\\]{1,2000})""",
      """"endpoint.os\\{0,20}":\\{0,20}"({os}[^"\\]{1,2000})"""
    
}
```