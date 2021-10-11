#### Parser Content
```Java
{
Name = symantec-epp-network-alert-1
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature ID""", """Denial of Service""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]{1,2000})\s""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),([^,]{0,2000},){3}Inbound,({protocol}\w+),([^,]{0,2000},){9}Local Port ({dest_port}\d{1,100}),""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Remote:\s{0,100}(?:0+|({src_host}[^,]{1,2000})),Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({src_host}[^,]{1,2000})),([^,]{0,2000},){3}Outbound,({protocol}\w+),""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Remote:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),Outbound,([^,]{0,2000},){10}Remote Port ({dest_port}\d{1,100}),""",
    """Remote Host Name:\s{0,100}(|({src_host}[\w\-.]{1,2000})),(Remote Host IP:\s{0,100}(?:0+|({src_ip}[A-Fa-f:\d.]{1,2000})),)?.*?,Inbound,({protocol}\w+),""",
    """Remote Host Name:\s{0,100}(|({dest_host}[\w\-.]{1,2000}),),(Remote Host IP:\s{0,100}(?:0+|({dest_ip}[A-Fa-f:\d.]{1,2000})))?.*?,Outbound,({protocol}\w+),""",
    """Local Host IP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}).*?,Outbound,({protocol}\w+),""",
    """Local Host IP:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000}).*?,Inbound,({protocol}\w+),""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User( Name)?:\s{0,100}(none|({user}[^,]{1,2000})),""",
    """Domain( Name)?:\s{0,100}({domain}[^,\s]{1,2000}),""",
    """SymantecServer:\s{0,100}.*?({alert_name}Denial of Service[^:]{1,2000}?)\s{0,100}Description:""",
    """\W\s{1,100}Description:\s{0,100}({additional_info}[^\.:]{1,2000})"""
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