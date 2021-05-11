#### Parser Content
```Java
{
Name = s-process-alert-carbonblack
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ "watchlist.hit", "watchlist_name" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"hostname"\s{0,100}:\s{0,100}"({host}[^\s"]+)"""",
    """"type":"({alert_type}[^"]+)""",
    """"timestamp"\s{0,100}:\s{0,100}({time}[\d]+)""",
    """computer_name":"({dest_host}[^"]+)""",
    """interface_ip"{1,20}:"{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """username"{1,20}:"{1,20}(({domain}[^\\"]+)\\+)?({user}[^"]+)""",
    """sensor_id":"?({sensor_id}[^"\,]+)""",
    """md5":"({md5}[^"]+)""",
    """alert_severity"{1,20}:"{1,20}({alert_severity}[^"]+)""",
    """watchlist_name"{1,20}:"{1,20}({alert_name}[^"]+)""",
    """unique_id"{1,20}:"{1,20}\{?({alert_id}[^\}"]+)""",
    """os_type"{1,20}:"{1,20}({os}[^"]+)""",
    """"process_name"\s{0,100}:\s{0,100}"({process_name}[^"]+)"""",
    """"(process_)?path"\s{0,100}:\s{0,100}"({process}({directory}([^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"observed_filename"\s{0,100}:\s{0,100}\[?"({process}({directory}([^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"process_guid":"({process_guid}[^"]+)""",
    """"ioc_attr"\s{0,100}:\s{0,100}"({ioc}([^"\\]|(\\\\)*\\"|\\)+)"""",
    """"ioc_value"\s{0,100}:\s{0,100}"({ioc}[^"]+)"""",
    """"parent_guid"\s{0,100}:\s{0,100}"({parent_process_guid}[^"]+)""",
    """"parent_name"\s{0,100}:\s{0,100}"({parent_process}[^"]+)""",
    """"cmdline"\s{0,100}:\s{0,100}"\\?"({command_line}[^"]+?)\\?"""",
    """"host_type"\s{0,100}:\s{0,100}"({host_type}[^"]+)"""",
  ]
  DupFields = [ "process->path","directory->process_directory" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```