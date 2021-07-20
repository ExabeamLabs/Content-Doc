#### Parser Content
```Java
{
Name = s-mcafee-dlp-alert-2
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """IncidentId=""" , """src_device=""" , """dest_dns""" , """Policy"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wtimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """\Wsignature="{0,20}({alert_name}.+?)"""",
    """\WIncidentId="{0,20}({signature_id}\d{1,100})""",
    """\Wevent_description="{0,20}({additional_info}.+?)"""",
    """\WDLP_FileName=?"{0,20}({file_name}.+?)"""",
    """\W(logon_)?user="{0,20}(N\/A|\s{1,100}|NULL|(({domain}[^\\]{1,2000})\\+)?({user}[^\s,"]{1,2000}))"""",
    """\Wdest_dns="{0,20}({src_host}[^"]{1,2000})"""
    """\Wdest_nt_host="{0,20}({src_host}[^\s"]{1,2000})""",
    """\Wsrc_ip="{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WPolicy="({policy}[^"]{1,2000})""",
    """\Wapp_file_name="({process_name}[^"]{1,2000})""",
    """app_prod_name="({app}[^"]{1,2000})""",
    """device_description="({device_id}[^"]{1,2000})"""
    
  ]
}
```