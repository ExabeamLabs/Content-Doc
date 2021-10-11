#### Parser Content
```Java
{
Name = symantec-epp-network-alert-3
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature ID""", """Unsolicited incoming ARP reply detected""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]{1,2000})\s""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),([^,]{0,2000},){3}Inbound,([^,]{0,2000},){9}Local Port ({dest_port}\d{1,100}),""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Remote:\s{0,100}(?:0+|({src_host}[^,]{1,2000})),Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({src_host}[^,]{1,2000})),([^,]{0,2000},){3}Outbound,""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Remote:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),Outbound,([^,]{0,2000},){10}Remote Port ({dest_port}\d{1,100}),""",
    """(Inbound|Outbound),({protocol}\w+),""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{0,100}(?:none|({user}[^,]{1,2000})),""",
    """Domain:\s{0,100}({domain}[^,\s]{1,2000}),""",
    """({alert_name}Unsolicited incoming ARP reply detected)""",
    """MD-5: [^,]{0,2000},"{0,20}({additional_info}.+?)(\s{1,100}|"{1,20}),Local:""",
    """Domain\s{0,100}(Name)?:\s{0,100}({domain}[^,\s]{1,2000}),""",
    """User\s{0,100}(Name)?:\s{0,100}(?:none|({user}[^,]{1,2000})),""",
    """(Inbound|Outbound|Unknown),({protocol}\w+),"""
    """Remote Host Name:\s{0,100}({dest_host}[^\s,]{1,2000})""",
    """Remote Host IP:\s{0,100}({dest_ip}[A-Fa-f.\d]{1,2000})""",
    """Remote Host MAC:\s{0,100}({dest_mac}[A-Fa-f.\d]{1,2000})""",
    """Local Host IP:\s{0,100}({src_ip}[A-Fa-f.\d]{1,2000})""",
    """Local Port:\s{0,100}({src_port}\d{1,100})""",
    """Remote Port:\s{0,100}({dest_port}\d{1,100})""",

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