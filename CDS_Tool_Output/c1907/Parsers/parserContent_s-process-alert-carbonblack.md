#### Parser Content
```Java
{
Name = s-process-alert-carbonblack
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ "watchlist.hit", "watchlist_name" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"hostname"\s*:\s*"({host}[^\s"]+)"""",
    """"type":"({alert_type}[^"]+)""",
    """"timestamp"\s*:\s*({time}[\d]+)""",
    """computer_name":"({dest_host}[^"]+)""",
    """interface_ip"+:"+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """username"+:"+(({domain}[^\\"]+)\\+)?({user}[^"]+)""",
    """sensor_id":"?({sensor_id}[^"\,]+)""",
    """md5":"({md5}[^"]+)""",
    """alert_severity"+:"+({alert_severity}[^"]+)""",
    """watchlist_name"+:"+({alert_name}[^"]+)""",
    """unique_id"+:"+\{?({alert_id}[^\}"]+)""",
    """os_type"+:"+({os}[^"]+)""",
    """"process_name"\s*:\s*"({process_name}[^"]+)"""",
    """"(process_)?path"\s*:\s*"({process}({directory}([^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"observed_filename"\s*:\s*\[?"({process}({directory}([^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"process_guid":"({process_guid}[^"]+)""",
    """"ioc_attr"\s*:\s*"({ioc}([^"\\]|(\\\\)*\\"|\\)+)"""",
    """"ioc_value"\s*:\s*"({ioc}[^"]+)"""",
    """"parent_guid"\s*:\s*"({parent_process_guid}[^"]+)""",
    """"parent_name"\s*:\s*"({parent_process}[^"]+)""",
    """"cmdline"\s*:\s*"\\?"({command_line}[^"]+?)\\?"""",
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