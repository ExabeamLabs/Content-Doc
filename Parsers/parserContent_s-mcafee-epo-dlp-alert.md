#### Parser Content
```Java
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