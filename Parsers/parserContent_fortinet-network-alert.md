#### Parser Content
```Java
{
Name = fortinet-network-alert
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype=ips""", """action=detected""", """service=""", """date=""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="?({host}[^"]+?)"?(\s+\w+=|\s*$)""",
    """\Wprofile="({alert_type}[^"]+)"""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wseverity="?({alert_severity}\w+)""",
    """\Wsrcport=({src_port}\d+)""",
    """\Wdstport=({dest_port}\d+)""",
    """\Wservice="?({protocol}\w+)""",
    """\Wattack="({alert_name}[^"]+)"""",
    """\Wmsg="({additional_info}[^"]+)"""",
    """\Waction="?({action}[^"]+?)"?(\s+\w+=|\s*$)""",
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description","alert_severity->sourceSeverity"]
    NameTemplate = """Fortinet Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```