#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-alert-5
  Lms = Direct
  DataType = "alert"
  Conditions = [ """"dataSource.name\":\"SentinelOne\"""", """"event.category\":\"indicators\"""", """"event.type\":\"Behavioral Indicators\"""" ]
  Fields = ${SentinelOneParserTemplates.json-sentinelone-edr-events.Fields} [
    """"src\.process\.parent\.image\.path\\{0,20}":\\{0,20}"{1,100}\s{0,100}({parent_process}({parent_process_directory}[^@]{1,2000}?)[\\\/]{0,2000}({parent_process_name}[^"\\\/]{1,2000}))\\{0,20}"""",
    """"src\.process\.image\.path\\{0,20}":\\{0,20}"({process_path}({process_directory}(:?[\w:]{1,2000})?[^"]{0,2000}\\)({process_name}[^"\\]{1,2000}))\\{0,20}"""",
    """"src\.process\.pid\\{0,20}":({process_id}\d{1,100})""",
    """"src\.process\.cmdline\\{0,20}":\\{0,20}"({command_line}.{1,3000}?)\\{0,20}",""",
    """"event\.id\\{0,20}":\\{0,20}"({event_code}[^"\\]{1,2000})""",
    """"indicator\.category\\{0,20}":\\{0,20}"({alert_type}[^"]{1,2000}?)\\{0,20}"""",
    """"indicator\.name\\{0,20}":\\{0,20}"({alert_name}[^"]{1,2000}?)\\{0,20}"""",
    """"indicator\.description\\{0,20}":\\{0,20}"({additional_info}.{1,2000}?)\\{0,20}",\\{0,20}""""
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