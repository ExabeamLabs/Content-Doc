#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-process-network
  Lms = Direct
  DataType = "process-network"
  Conditions = [ """"dataSource.name":"SentinelOne"""", """"i.scheme":"edr"""", """"event.category":"ip"""", """"event.type":"IP Listen"""" ]
  Fields = ${SentinelOneParserTemplates.json-sentinelone-edr-events.Fields} [
    """"endpoint.type":"({device_type}[^"]{1,2000})"""",
    """"src.process.parent.image.path":"{1,20}\s{0,100}({parent_process}({parent_process_directory}[^@]+?)[\\\/]{0,2000}({parent_process_name}[^"\\\/]{1,2000}))"""",
    """"src.process.image.path":"({process_path}({process_directory}(:?[\w:]{1,2000})?[^"]{0,2000}\\)({process_name}[^"]{1,2000}))"""",
    """"src.process.pid":({process_id}\d{1,100})""",
    """"src.process.cmdline":"({command_line}.{1,3000}?)",""",
    """"event.id":"({event_code}[^"]{1,100})""",
    """event.name":"({operation_type}[^"]{1,2000})""",
  ]

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