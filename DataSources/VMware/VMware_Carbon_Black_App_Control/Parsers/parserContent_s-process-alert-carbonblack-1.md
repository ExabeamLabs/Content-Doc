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
    """"timestamp"\s{0,100}:\s{0,100}"?({time}[\d]+)""",
    """"hostname"\s{0,100}:\s{0,100}"({host}[^\s"]+)"""",
    """"type"\s{0,100}:\s{0,100}"({alert_type}[^"]+)"""",
    """"computer_name"\s{0,100}:\s{0,100}"({dest_host}[^"]+)"""",
    """"interface_ip"\s{0,100}:\s{0,100}"({dest_ip}[A-Fa-f:\d.]+)""",
    """"username"\s{0,100}:\s{0,100}"(({domain}[^\\"]+)\\+)?({user}[^\\\s"]+)""",
    """"sensor_id"\s{0,100}:\s{0,100}"?({sensor_id}[^",]+)""",
    """"process_md5"\s{0,100}:\s{0,100}"({md5}[^"]+)"""",
    """"unique_id"\s{0,100}:\s{0,100}"\{?({alert_id}[^\}"]+)""",
    """"os_type"\s{0,100}:\s{0,100}"({os}[^"]+)""",
    """"process_name"\s{0,100}:\s{0,100}"({process_name}[^"]+)"""",
    """"path"\s{0,100}:\s{0,100}"({process}({directory}([^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"process_guid"\s{0,100}:\s{0,100}"({process_guid}[^"]+)"""",
    """"ioc_query_string"\s{0,100}:\s{0,100}"({ioc}.+?)",""",
    """"parent_guid"\s{0,100}:\s{0,100}"({parent_process_guid}[^"]+)""",
    """"parent_name"\s{0,100}:\s{0,100}"({parent_process}[^"]+)""",
    """"cmdline"\s{0,100}:\s{0,100}"\\?"({command_line}[^"]+?)\\?"""",
    """"host_type"\s{0,100}:\s{0,100}"({host_type}[^"]+)"""",
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