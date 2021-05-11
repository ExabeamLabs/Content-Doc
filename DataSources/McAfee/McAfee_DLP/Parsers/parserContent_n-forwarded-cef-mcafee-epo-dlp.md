#### Parser Content
```Java
{
Name = n-forwarded-cef-mcafee-epo-dlp
    Vendor = McAfee
    Product = McAfee DLP
    Lms = NitroCefSyslog
    DataType = "dlp-alert"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|ESM|""", """|359-""", """act=alert""" ]
    Fields = [ 
      """\send=({time}\d{1,100})""",
      """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sshost=({src_host}[^\s]+)""",
      """\|McAfee\|ESM\|[^\|]+\|359-({signature_id}[^\|]+)""",
      """\seventId=({alert_id}[^\s]+)\s[^\s]+?=""",
      """\snitroThreat_Name=({alert_name}.+?)\s[^\s]+?=""",
      """\snitroObject_Type=({alert_type}.+?)\s[^\s]+?=""",
      """\sduser=([^\\=]+?\\)?({user}.+?)\s[^\s]+?=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\snitroProcess_Name=({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+))\s[^\s]+="""
    ]
    DupFields = ["directory->process_directory"]
  }
```