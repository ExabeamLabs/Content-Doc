#### Parser Content
```Java
{
Name = azure-memorymetircs-json
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "azure-metrics"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Type":"InsightsMetrics""", """Namespace":"Memory""", """Name":"AvailableMB""" ]
  Fields = [
    """"{1,20}TenantId"{1,20}:\s{0,100}"{1,20}({tenant_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}TimeGenerated\s{0,100}\[UTC\]?"{1,20}:\s{0,100}"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"{1,20}""",
    """"{1,20}Computer"{1,20}:\s{0,100}"{1,20}({src_host}[^"]{1,2000})"{1,20}""",
    """"{1,20}Namespace"{1,20}:\s{0,100}"{1,20}({metric_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}Name"{1,20}:\s{0,100}"{1,20}({metric_name}[^"]{1,2000})"{1,20}""",
    """"{1,20}Val"{1,20}:\s{0,100}({metric_value}[^",\s]{1,2000})""",
    """memorySizeMB\\?"{1,20}:\s{0,100}({memory_size}[^",\s]{1,2000})""",
    """"{1,20}_ResourceId"{1,20}:\s{0,100}"{1,20}({resource}({resource_path}[^"]{1,2000})\/({resource_name}[^"]{1,2000})|[^"]{1,2000})"{1,20}""",
  ]
  DupFields = [ "metric_value->available_memory" ]


}
```