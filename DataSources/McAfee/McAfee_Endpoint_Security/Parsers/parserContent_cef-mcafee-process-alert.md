#### Parser Content
```Java
{
Name = cef-mcafee-process-alert
  DataType = "process-alert"
  IsHVF = true
  Conditions = [ """CEF:""", """|McAfee|ePolicy Orchestrator|""", """Access Protection rule violation detected and """ ]
  Fields = ${McAfeeParserTemplates.cef-mcafee-epo-alert.Fields}[
    """Access Protection rule violation detected and ({outcome}(NOT )?blocked)""",
    """\sshost=(_|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\ssproc=({process}({directory}[^=]*?[\\\/]+)?({process_name}[^=\\\/]+))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
cef-mcafee-epo-alert = {
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdhost=({src_host}[^\s]+)""",
    """\sdst=(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sfname=({malware_url}.+?)\s{1,100}(\w+=)""",
    """\sfname=({malware_url}[^=]+?\\+({malware_file_name}[^\\=]+?))\s{1,100}\w+=""",
    """\sduser=(SYSTEM|N\/A|(({domain}[^=\\]+)\\+)?({user}.+?))\s{1,100}(\w+=|$)""",
    """\sdntdom=(?:\(none\)|({domain}[^\s]+))""",
    """\seventId=({alert_id}\d{1,100})""",
    """\sexternalId=({alert_id}\d{1,100})""",
    """\|McAfee\|ePolicy[^|]+?\|[^|]+?\|[^|]+?\|({alert_name}[^.|]+)""",
    """\scs1=(?:none|({alert_name}.+?))\s{1,100}(\w+=|$)""",
    """\scat=({threat_category}.+?)\s{1,100}(\w+=|$)""",
    """\|McAfee\|ePolicy[^|]+?\|[^|]+?\|[^|]+?\|({alert_type}[^.|]+)""",
    """\|McAfee\|ePolicy[^|]+?\|[^|]+?\|[^|]+?\|[^|]+?\|({alert_severity}[^\|]+)""",
    """\scategoryOutcome=/?({outcome}.+?)\s{1,100}(\w+=|$)""",
  ]

```