#### Parser Content
```Java
{
Name = q-process-alert-carbonblack-1
  Vendor = VMware
  Product = App Control
  Lms = QRadar
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """0|CB|CB|""", """type=feed.""" ]
  Fields = [
    """\Wtimestamp=({time}\d{10})""",
    """\d{1,100}:\d{1,100}:\d{1,100}Z\s{1,100}({host}[\w\-\.]{1,2000})\s{1,100}[^\[\]]{0,2000}\[\d{1,100}\]:""",
    """hostname=({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """0\|CB\|CB\|[^|]{0,2000}\|({alert_type}[^|]{1,2000})\|""",
    """\Wcomputer_name=(|({dest_host}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Winterface_ip=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wusername=(({domain}[^\\]{1,2000})\\+)?(|({user}[^"]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsensor_id=(|({sensor_id}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wioc_type=md5[^@]{1,2000}?ioc_value=(|({md5}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(process_)?md5=(|({md5}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcmdline="{1,20}(\\+\?+\\+)?({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))"{1,20}""",
    """\Wunique_id=(|({alert_id}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wos_type=(|({os}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprocess_name=(|({process_name}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(process_)?path=(|({path}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(process_)?path=(|({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000})))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprocess_guid=(|({process_guid}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wioc_value=(|({ioc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wioc_query_string=(|({ioc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wparent_guid=(|({parent_process_guid}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\Wparent_name=(|({parent_process}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\Wcmdline=\s{0,100}({command_line}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\Wtype=(|({alert_type}[^"]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wreport_score=({alert_severity}\d{1,100})""",
    """\Whost_type=(|({host_type}[^"]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """feed_name=(|({alert_name}[^"]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)"""
  ]
  DupFields = [ "directory->process_directory", "ioc->additional_info" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]

}
```