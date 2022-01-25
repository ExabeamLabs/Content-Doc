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
    """\Wdevname="?({host}[^"]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprofile="({alert_type}[^"]{1,2000})"""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wseverity="?({alert_severity}\w+)""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wservice="?({protocol}\w+)""",
    """\Wattack="({alert_name}[^"]{1,2000})"""",
    """\Wmsg="({additional_info}[^"]{1,2000})"""",
    """\Waction="?({action}[^"]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description","alert_severity->sourceSeverity"]
    NameTemplate = """Fortinet Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```