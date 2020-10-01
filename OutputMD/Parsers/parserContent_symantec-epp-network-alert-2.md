#### Parser Content
```Java
{
Name = symantec-epp-network-alert-2
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature ID""", """traffic from IP address""", """block""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s+\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]+)\s""",
    """Local:\s*({dest_ip}[a-fA-F:\.\d]+),Local:\s*(?:0+|({dest_host}[^,]+)),([^,]*,){3}Inbound,([^,]*,){9}Local Port ({dest_port}\d+),""",
    """Remote:\s*({src_ip}[a-fA-F:\.\d]+),Remote:\s*(?:0+|({src_host}[^,]+)),Inbound,""",
    """Local:\s*({src_ip}[a-fA-F:\.\d]+),Local:\s*(?:0+|({src_host}[^,]+)),([^,]*,){3}Outbound,""",
    """Remote:\s*({dest_ip}[a-fA-F:\.\d]+),Remote:\s*(?:0+|({dest_host}[^,]+)),Outbound,([^,]*,){10}Remote Port ({dest_port}\d+),""",
    """Local:\s*({dest_ip}[a-fA-F:\.\d]+),Local:\s*(?:0+|({dest_host}[^,]+)),([^,]*,){3}Unknown,([^,]*,){9}Local Port ({dest_port}\d+),""",
    """Remote:\s*({src_ip}[a-fA-F:\.\d]+),Remote:\s*(?:0+|({src_host}[^,]+)),([^,]*,){3}Unknown,""",
    """(Inbound|Outbound|Unknown),({protocol}\w+),""",
    """Begin:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User:\s*(?:none|({user}[^,]+)),""",
    """Domain:\s*({domain}[^,\s]+),""",
    """({alert_name}The traffic from IP address .+? was blocked)""",
    """MD-5: [^,]*,"*({additional_info}.+?)(\s+|"+),Local:"""
  ]
  DupFields = [ "alert_name->alert_type"]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description"]
    NameTemplate = """Symantec Network Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```