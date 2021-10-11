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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]{1,2000})\s""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),([^,]{0,2000},){3}Inbound,({protocol}\w+),([^,]{0,2000},){8}Local Port ({dest_port}\d{1,100}),""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Remote:\s{0,100}(?:0+|({src_host}[^,]{1,2000})),Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({src_host}[^,]{1,2000})),([^,]{0,2000},){3}Outbound,({protocol}\w+),""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Remote:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),Outbound,([^,]{0,2000},){10}Remote Port ({dest_port}\d{1,100}),""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{0,100}({user}[^,]{1,2000}),""",
    """Domain:\s{0,100}({domain}[^,]{1,2000}),""",
    """({alert_name}Somebody is scanning your computer)""",
    """[^"]{1,2000}"({additional_info}[^"\.]{1,2000})"""
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