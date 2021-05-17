#### Parser Content
```Java
{
Name = s-process-alert-carbonblack-1
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """"type":"feed.""", """"cb_server":"""" ]
  Fields = [
    """"timestamp"\s{0,100}:\s{0,100}"?({time}[\d]{1,2000})""",
    """"hostname"\s{0,100}:\s{0,100}"({host}[^\s"]{1,2000})"""",
    """"type"\s{0,100}:\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"computer_name"\s{0,100}:\s{0,100}"({dest_host}[^"]{1,2000})"""",
    """"interface_ip"\s{0,100}:\s{0,100}"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"username"\s{0,100}:\s{0,100}"(({domain}[^\\"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
    """"sensor_id"\s{0,100}:\s{0,100}"?({sensor_id}[^",]{1,2000})""",
    """"process_md5"\s{0,100}:\s{0,100}"({md5}[^"]{1,2000})"""",
    """"unique_id"\s{0,100}:\s{0,100}"\{?({alert_id}[^\}"]{1,2000})""",
    """"os_type"\s{0,100}:\s{0,100}"({os}[^"]{1,2000})""",
    """"process_name"\s{0,100}:\s{0,100}"({process_name}[^"]{1,2000})"""",
    """"path"\s{0,100}:\s{0,100}"({process}({directory}([^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""",
    """"process_guid"\s{0,100}:\s{0,100}"({process_guid}[^"]{1,2000})"""",
    """"ioc_query_string"\s{0,100}:\s{0,100}"({ioc}.+?)",""",
    """"parent_guid"\s{0,100}:\s{0,100}"({parent_process_guid}[^"]{1,2000})""",
    """"parent_name"\s{0,100}:\s{0,100}"({parent_process}[^"]{1,2000})""",
    """"cmdline"\s{0,100}:\s{0,100}"\\?"({command_line}[^"]{1,2000}?)\\?"""",
    """"host_type"\s{0,100}:\s{0,100}"({host_type}[^"]{1,2000})"""",
  ]
  DupFields = [ "process->path", "ioc->alert_name" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```