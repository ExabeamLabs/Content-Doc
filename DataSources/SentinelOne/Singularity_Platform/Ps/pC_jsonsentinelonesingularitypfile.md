#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-file
  Lms = Direct
  DataType = "file-operations"
  Conditions = [ """"dataSource.name":"SentinelOne"""", """"i.scheme":"edr"""", """"event.category":"file"""", """"event.type":""" ]

json-sentinelone-edr-events = {
    Vendor = SentinelOne
    Product = "Singularity Platform"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"timestamp":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
      """"event\.type":"({event_name}[^"]{1,2000})""",
      """"endpoint\.name":"({dest_host}[^"]{1,2000})""",
      """"task\.path":"({file_path}({file_dir}[^"]{0,2000}?)({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\\."]{1,2000}?))?))"""",
      """process\.name":"({process_name}[^"]{1,2000})""",
      """"endpoint.os":"({os}[^"]{1,2000})"""
    
}
```