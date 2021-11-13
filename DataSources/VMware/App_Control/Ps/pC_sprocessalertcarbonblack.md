#### Parser Content
```Java
{
Name = s-process-alert-carbonblack
  Vendor = VMware
  Product = App Control
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ "watchlist.hit", "watchlist_name" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"hostname"\s{0,100}:\s{0,100}"({host}[^\s"]{1,2000})"""",
    """"type":"({alert_type}[^"]{1,2000})""",
    """"timestamp"\s{0,100}:\s{0,100}({time}[\d]{1,2000})""",
    """computer_name":"({dest_host}[^"]{1,2000})""",
    """interface_ip"{1,20}:"{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """username"{1,20}:"{1,20}(({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000})""",
    """sensor_id":"?({sensor_id}[^"\,]{1,2000})""",
    """md5":"({md5}[^"]{1,2000})""",
    """alert_severity"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})""",
    """watchlist_name"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
    """unique_id"{1,20}:"{1,20}\{?({alert_id}[^\}"]{1,2000})""",
    """os_type"{1,20}:"{1,20}({os}[^"]{1,2000})""",
    """"process_name"\s{0,100}:\s{0,100}"({process_name}[^"]{1,2000})"""",
    """"(process_)?path"\s{0,100}:\s{0,100}"({process}({directory}([^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""",
    """"observed_filename"\s{0,100}:\s{0,100}\[?"({process}({directory}([^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""",
    """"process_guid":"({process_guid}[^"]{1,2000})""",
    """"ioc_attr"\s{0,100}:\s{0,100}"({ioc}([^"\\]|(\\\\)*\\"|\\)+)"""",
    """"ioc_value"\s{0,100}:\s{0,100}"({ioc}[^"]{1,2000})"""",
    """"parent_guid"\s{0,100}:\s{0,100}"({parent_process_guid}[^"]{1,2000})""",
    """"parent_name"\s{0,100}:\s{0,100}"({parent_process}[^"]{1,2000})""",
    """"cmdline"\s{0,100}:\s{0,100}"\\?"({command_line}[^"]{1,2000}?)\\?"""",
    """"host_type"\s{0,100}:\s{0,100}"({host_type}[^"]{1,2000})"""",
  ]
  DupFields = [ "process->path","directory->process_directory" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]

}
```