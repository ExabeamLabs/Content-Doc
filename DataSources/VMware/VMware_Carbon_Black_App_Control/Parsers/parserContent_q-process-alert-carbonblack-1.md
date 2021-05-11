#### Parser Content
```Java
{
Name = q-process-alert-carbonblack-1
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = QRadar
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """0|CB|CB|""", """type=feed.""" ]
  Fields = [
    """\Wtimestamp=({time}\d{10})""",
    """\d{1,100}:\d{1,100}:\d{1,100}Z\s{1,100}({host}[\w\-\.]+)\s{1,100}[^\[\]]*\[\d{1,100}\]:""",
    """hostname=({host}[^=]+?)\s{1,100}\w+=""",
    """0\|CB\|CB\|[^|]*\|({alert_type}[^|]+)\|""",
    """\Wcomputer_name=(|({dest_host}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Winterface_ip=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wusername=(({domain}[^\\]+)\\+)?(|({user}[^"]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsensor_id=(|({sensor_id}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wioc_type=md5[^@]+?ioc_value=(|({md5}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(process_)?md5=(|({md5}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcmdline="{1,20}(\\+\?+\\+)?({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+))"{1,20}""",
    """\Wunique_id=(|({alert_id}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wos_type=(|({os}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprocess_name=(|({process_name}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(process_)?path=(|({path}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(process_)?path=(|({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+)))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprocess_guid=(|({process_guid}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wioc_value=(|({ioc}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wioc_query_string=(|({ioc}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wparent_guid=(|({parent_process_guid}[^=]+?))\s{0,100}(\w+=|$)""",
    """\Wparent_name=(|({parent_process}[^=]+?))\s{0,100}(\w+=|$)""",
    """\Wcmdline=\s{0,100}({command_line}[^=]+?)\s{0,100}(\w+=|$)""",
    """\Wtype=(|({alert_type}[^"]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wreport_score=({alert_severity}\d{1,100})""",
    """\Whost_type=(|({host_type}[^"]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """feed_name=(|({alert_name}[^"]+?))(\s{1,100}\w+=|\s{0,100}$)"""
  ]
  DupFields = [ "directory->process_directory", "ioc->additional_info" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```