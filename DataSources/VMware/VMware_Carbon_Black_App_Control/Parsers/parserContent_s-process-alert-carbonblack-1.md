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
    """"timestamp"\s*:\s*"?({time}[\d]+)""",
    """"hostname"\s*:\s*"({host}[^\s"]+)"""",
    """"type"\s*:\s*"({alert_type}[^"]+)"""",
    """"computer_name"\s*:\s*"({dest_host}[^"]+)"""",
    """"interface_ip"\s*:\s*"({dest_ip}[A-Fa-f:\d.]+)""",
    """"username"\s*:\s*"(({domain}[^\\"]+)\\+)?({user}[^\\\s"]+)""",
    """"sensor_id"\s*:\s*"?({sensor_id}[^",]+)""",
    """"process_md5"\s*:\s*"({md5}[^"]+)"""",
    """"unique_id"\s*:\s*"\{?({alert_id}[^\}"]+)""",
    """"os_type"\s*:\s*"({os}[^"]+)""",
    """"process_name"\s*:\s*"({process_name}[^"]+)"""",
    """"path"\s*:\s*"({process}({directory}([^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"process_guid"\s*:\s*"({process_guid}[^"]+)"""",
    """"ioc_query_string"\s*:\s*"({ioc}.+?)",""",
    """"parent_guid"\s*:\s*"({parent_process_guid}[^"]+)""",
    """"parent_name"\s*:\s*"({parent_process}[^"]+)""",
    """"cmdline"\s*:\s*"\\?"({command_line}[^"]+?)\\?"""",
    """"host_type"\s*:\s*"({host_type}[^"]+)"""",
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