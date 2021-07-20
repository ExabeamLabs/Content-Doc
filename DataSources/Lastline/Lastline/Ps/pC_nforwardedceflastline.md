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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\sshost=({src_host}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\ssuser=({user}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|McAfee\|.*?\|.*?\|.*?\|({alert_name}.*?)\|"""
    """\scat=({alert_type}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\snitroSubcategory=({alert_type}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\snitroThreat_Category=({alert_type}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\sproto=({protocol}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\sdpt=({dest_port}\d{1,100})""",
    """nitro({hash_type}SHA1)=({file_hash}[^\s]{1,2000}?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\snitroUniqueId=({alert_id}\d{1,100})(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\snitroDevice_URL=({additional_info}[^\s]{1,2000}?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)"""
  ]
  DupFields = ["host->dest_host"]
}
```