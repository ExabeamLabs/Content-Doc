#### Parser Content
```Java
{
Name = n-forwarded-cef-lastline
  Vendor = Lastline
  Product = Lastline
  Lms = NitroCefSyslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|McAfee|", "deviceExternalId=Lastline Manager" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\srt=({time}\d+)""",
    """\sshost=({src_host}.+?)(\s+\w+=|"*\s*$)""",
    """\ssuser=({user}.+?)(\s+\w+=|"*\s*$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|McAfee\|.*?\|.*?\|.*?\|({alert_name}.*?)\|"""
    """\scat=({alert_type}.+?)(\s+\w+=|"*\s*$)""",
    """\snitroSubcategory=({alert_type}.+?)(\s+\w+=|"*\s*$)""",
    """\snitroThreat_Category=({alert_type}.+?)(\s+\w+=|"*\s*$)""",
    """\sproto=({protocol}.+?)(\s+\w+=|"*\s*$)""",
    """\sdpt=({dest_port}\d+)""",
    """nitro({hash_type}SHA1)=({file_hash}[^\s]+?)(\s+\w+=|"*\s*$)""",
    """\snitroUniqueId=({alert_id}\d+)(\s+\w+=|"*\s*$)""",
    """\snitroDevice_URL=({additional_info}[^\s]+?)(\s+\w+=|"*\s*$)"""
  ]
  DupFields = ["host->dest_host"]
}
```