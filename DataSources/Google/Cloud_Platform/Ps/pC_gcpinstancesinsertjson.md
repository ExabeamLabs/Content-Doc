#### Parser Content
```Java
{
Name = gcp-instancesinsert-json
  DataType = "gcp-instance-create"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """googleapis.com""", """"methodName":""", """compute.instances.insert"""" ]
  Fields = ${GcpParserTemplates.gcp-cloudaudit-json.Fields}[
    """"source({source_resource_type}Snapshot)":\s{0,100}"({source_resource}[^"\\]{1,2000})"""",
    """"source({source_resource_type}Image)":\s{0,100}"({source_resource}[^"\\]{1,2000})"""",
    """"source({source_resource_type}Disk)":\s{0,100}"({source_resource}[^"\\]{1,2000})"""",
    """"machineType":\s{0,100}"({machine_type}[^"\\]{1,2000})"""",
    """"email":\s{0,100}"({linked_service_account}[^"\\]{1,2000})"""",
    """"subnetwork":\s{0,100}"({subnetwork}[^"\\]{1,2000})"""",
  ]

gcp-cloudaudit-json = {
    Vendor = Google
    Product = Cloud Platform
    Lms = Direct
    DataType = "gcp-general-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"{1,20}logName"{1,20}:\s{0,100}"{1,20}({log_type}[^",\s\[\{]{1,200})"{1,20}""",
      """"{1,20}log-name"{1,20}:\s{0,100}"{1,20}({log_type}[^",\s\[\{]{1,200})"{1,20}""",
      """"status":.+"code":\s{0,100}({result_code}\d{1,100})""",
      """"status":.+"message":\s{0,100}({failure_reason}[^\\},]{1,250})""",
      """"principalEmail":\s{0,100}"({user}[^"]{1,2000}?@({domain}[^"@]{1,2000})|[^"]{1,2000})"""",
      """"callerIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
      """"callerSuppliedUserAgent":\s{0,100}"({user_agent}[^"]{1,2000})""",
      """"methodName":\s{0,100}"({operation}[^"]{1,2000})""",
      """"resourceName":\s{0,100}"({resource}({resource_path}[^"]{1,2000})\/({resource_name}[^"\/]{1,2000}))"""",
      """"serviceName":\s{0,100}"({service}[^"]{1,2000})""",
      """"resource":\s{0,100}\{\s{0,100}"type":\s{0,100}"({resource_type}[^"\\\/]{1,200})"""",
      """"{1,20}resource"{1,20}:[^\}]{0,1000}labels[^\}]{0,1000}"{1,20}project_id"{1,20}:\s{0,100}"{1,20}({project_id}[^"\\\/\}]{1,200})"{1,20}""",
      """"{1,20}resource"{1,20}:[^\}]{0,1000}labels[^\}]{0,1000}"{1,20}zone"{1,20}:\s{0,100}"{1,20}({zone}[^"\\\/\}]{1,200})"{1,20}""",
      """"{1,20}resource"{1,20}:[^\}]{0,1000}labels[^\}]{0,1000}"{1,20}location"{1,20}:\s{0,100}"{1,20}({region}[^"\\\/\}]{1,200})"{1,20}""",
      """"{1,20}resource"{1,20}:[^\}]{0,1000}labels[^\}]{0,1000}"{1,20}bucket_name"{1,20}:\s{0,100}"{1,20}({bucket}[^"\\\/\}]{1,200})"{1,20}""",
      """"{1,20}operation"{1,20}:[^\}]{0,1000}first"{1,20}:\s{0,100}({operation_first}[^"\\\/\}\s,]{1,200})""",
      """"{1,20}operation"{1,20}:[^\}]{0,1000}last"{1,20}:\s{0,100}({operation_last}[^"\\\/\}\s,]{1,200})""",
    
}
```