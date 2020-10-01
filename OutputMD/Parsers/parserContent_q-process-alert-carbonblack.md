#### Parser Content
```Java
{
Name = q-process-alert-carbonblack
  Vendor = Carbon Black
  Product = CB Protection
  Lms = QRadar
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """0|CB|CB|""", "watchlist.hit" ]
  Fields = [
    """exabeam_startTime=({time}\d{10})""",
    """timestamp=({time}\d{10})""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """0\|CB\|CB\|[^|]+\|({alert_type}[^|]+)\|""",
    """computer_name=({dest_host}.+?)\s+\w+=""",
    """interface_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """username=(({domain}[^\\]+)\\+)?({user}.+?)\s+\w+=""",
    """sensor_id=({sensor_id}.+?)\s+\w+=""",
    """(process_)?md5=({md5}.+?)\s+\w+=""",
    """cmdline="+(\\+\?+\\+)?({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+))"+""",
    """alert_severity=({alert_severity}.+?)\s+\w+=""",
    """alert_type=({alert_type}.+?)\s+\w+=""",
    """watchlist_name=({alert_name}.+?)(\s+\w+=|\s*$)""",
    """unique_id=\{?({alert_id}.+?)\}?\s+\w+=""",
    """os_type=({os}.+?)\s+\w+=""",
    """process_name=({process_name}.+?)\s+\w+=""",
    """\s(process_)?path=({path}.+?)\s+\w+=""",
    """\s(process_)?path=({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+))\s+\w+=""",
    """process_guid=({process_guid}.+?)\s+\w+=""",
    """ioc_value=({ioc}.+?)\s+\w+=""",
    """ioc_attr=({ioc}.+?)\s+\w+=""",
    """ioc_query_string=\(({ioc}.+?)\)""",
    """parent_guid=({parent_process_guid}.+?)\s*(\w+=|$)""",
    """parent_name=({parent_process}.+?)\s*(\w+=|$)""",
    """cmdline=({command_line}.+?)\s*(\w+=|$)""",
    """host_type=(|({host_type}.+?))\s*(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```