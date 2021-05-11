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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wtimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\WDLP_IncidentId="{0,20}({alert_id}\d{1,100})""",
    """\Wsignature="{0,20}({alert_name}.+?)"""",
    """\Wthreat_type="{0,20}({alert_type}.+?)"""",
    """\Wsignature_id="{0,20}({signature_id}\d{1,100})""",
    """\Wseverity_id="{0,20}({alert_severity}\d{1,100})""",
    """\Wevent_description="{0,20}({additional_info}.+?)"""",
    """\WDLP_FileName=?"{0,20}({file_name}.+?)"""",
    """\Wuser="{0,20}(N\/A|\s{1,100}|NULL|([^\\]+\\+)?({user}[^\s,"]+))"""",
    """\Wdest_nt_host="{0,20}({src_host}[^\s"]+)""",
    """\Wsrc_ip="{0,20}({src_ip}[A-Fa-f:\d.]+)""",
    """\Wprocess="{0,20}({process}({directory}(?:(\w+:)?[^:"]+)?[\\\/])?({process_name}[^\\"]+))""",
    """\Wos="{0,20}({os}[^"]+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```