#### Parser Content
```Java
{
Name = symantec-epp-network-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature string""", """Somebody is scanning your computer""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]+)\s""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),Local:\s{0,100}(?:0+|({dest_host}[^,]+)),([^,]*,){3}Inbound,({protocol}\w+),([^,]*,){8}Local Port ({dest_port}\d{1,100}),""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]+),Remote:\s{0,100}(?:0+|({src_host}[^,]+)),Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]+),Local:\s{0,100}(?:0+|({src_host}[^,]+)),([^,]*,){3}Outbound,({protocol}\w+),""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),Remote:\s{0,100}(?:0+|({dest_host}[^,]+)),Outbound,([^,]*,){10}Remote Port ({dest_port}\d{1,100}),""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{0,100}({user}[^,]+),""",
    """Domain:\s{0,100}({domain}[^,]+),""",
    """({alert_name}Somebody is scanning your computer)""",
    """[^"]+"({additional_info}[^"\.]+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description"]
    NameTemplate = """Symantec Network Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```