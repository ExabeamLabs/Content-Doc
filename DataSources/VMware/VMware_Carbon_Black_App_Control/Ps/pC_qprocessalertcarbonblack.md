#### Parser Content
```Java
{
Name = q-process-alert-carbonblack
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = QRadar
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """0|CB|CB|""", """watchlist.hit""" ]
  Fields = [
    """exabeam_startTime=({time}\d{10})""",
    """timestamp=({time}\d{10})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """hostname=({host}[^=]{1,2000}?)\s{1,100}\w+="""
    """0\|CB\|CB\|[^|]{1,2000}\|({alert_type}[^|]{1,2000})\|""",
    """computer_name=({dest_host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """interface_ip=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """username=(({domain}[^\\]{1,2000})\\+)?({user}[^=]{1,2000}?)\s{1,100}\w+=""",
    """sensor_id=({sensor_id}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\W(process_)?md5=(|({md5}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """cmdline="{1,20}(\\+\?+\\+)?({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))"{1,20}""",
    """alert_severity=({alert_severity}[^=]{1,2000}?)\s{1,100}\w+=""",
    """alert_type=({alert_type}[^=]{1,2000}?)\s{1,100}\w+=""",
    """watchlist_name=({additional_info}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """unique_id=\{?({alert_id}[^=]{1,2000}?)\}?\s{1,100}\w+=""",
    """os_type=({os}[^=]{1,2000}?)\s{1,100}\w+=""",
    """process_name=({process_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\s(process_)?path=({path}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\s(process_)?path=({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))\s{1,100}\w+=""",
    """process_guid=({process_guid}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ioc_value=({ioc}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ioc_attr=({ioc}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ioc_query_string=\(({ioc}[^=]{1,2000}?)\)""",
    """parent_guid=({parent_process_guid}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """parent_name=({parent_process}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """cmdline=({command_line}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """host_type=(|({host_type}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\W+type=({alert_name}[^=]{1,2000}?)\s{1,100}\w+="""
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