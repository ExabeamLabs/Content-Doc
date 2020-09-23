#### Parser Content
```Java
{
Name = n-cef-mcafee-alert
  Vendor = McAfee
  Product = McAfee Enterprise Security Manager
  Lms = NitroCefSyslog
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """deviceExternalId=McAfee_NSM_OPMNSMP3""" ]
  Fields = [
    """\|McAfee\|ESM\|([^|]+?\|){2}({alert_name}[^|]+)\|""",
    """\Wrt=({time}\d+)""",
    """\Wproto=({protocol}.*?)\s+(\w+=|$)""",
    """\Wcat=({alert_type}.*?)\s+(\w+=|$)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wshost=({src_host}.*?)\s+(\w+=|$)""",
    """\WnitroCategory=({threat_category}.*?)\s+(\w+=|$)""",
    """\Wsntdom=({domain}.*?)\s+(\w+=|$)"""
  ]
}

{
  Name = s-mcafee-epo-dlp-alert
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """product="Data Loss Prevention"""", """signature_id="""", """is_laptop="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wtimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\WDLP_IncidentId="*({alert_id}\d+)""",
    """\Wsignature="*({alert_name}.+?)"""",
    """\Wthreat_type="*({alert_type}.+?)"""",
    """\Wsignature_id="*({signature_id}\d+)""",
    """\Wseverity_id="*({alert_severity}\d+)""",
    """\Wevent_description="*({additional_info}.+?)"""",
    """\WDLP_FileName=?"*({file_name}.+?)"""",
    """\Wuser="*(N\/A|\s+|NULL|([^\\]+\\+)?({user}[^\s,"]+))"""",
    """\Wdest_nt_host="*({src_host}[^\s"]+)""",
    """\Wsrc_ip="*({src_ip}[A-Fa-f:\d.]+)""",
    """\Wprocess="*({process}({directory}(?:(\w+:)?[^:"]+)?[\\\/])?({process_name}[^\\"]+))""",
    """\Wos="*({os}[^"]+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```