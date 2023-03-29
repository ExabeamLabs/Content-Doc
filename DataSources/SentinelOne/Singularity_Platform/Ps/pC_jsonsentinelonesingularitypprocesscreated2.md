#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-process-created-2
  Lms = Direct
  DataType = "process-created"
  Conditions = [ """"dataSource.name\":\"SentinelOne\"""", """"event.category\":\"process\"""", """"event.type\":\"Process Creation\"""", """"endpoint.os\":\"windows\"""" ]
  Fields = ${SentinelOneParserTemplates.json-sentinelone-edr-events.Fields} [
    """"endpoint.type\\{0,20}":\\{0,20}"({device_type}[^"]{1,2000}?)\\{0,20}"""",
    """"src.process.image.sha256\\{0,20}":\s{0,100}\\{0,20}"+({hash_sha256}[^"\\]{1,2000})\\{0,20}"""",
    """"src.process.image.sha1\\{0,20}":\s{0,100}\\{0,20}"+({hash_sha1}[^"\\]{1,2000})\\{0,20}"""",
    """"src.process.user\\{0,20}":\\{0,20}"{0,100}((NT AUTHORITY|({domain}[^\\"]{1,2000}))[\\\/]{1,2000})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))\\{0,20}"""",
    """"src.process.parent.image.path\\{0,20}":\\{0,20}"{1,100}\s{0,100}({parent_process}({parent_process_directory}[^@]+?)[\\\/]{0,2000}({parent_process_name}[^"\\\/]{1,2000}))\\{0,20}"""",
    """"src.process.image.path\\{0,20}":\\{0,20}"({process_path}({process_directory}(:?[\w:]{1,2000})?[^"]{0,2000}\\)({process_name}[^"\\]{1,2000}))\\{0,20}"""",
    """"src.process.pid\\{0,20}":({process_id}\d{1,100})""",
    """"src.process.cmdline\\{0,20}":\\{0,20}"({command_line}.{1,2000}?)\\{0,20}",""",
  ]

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