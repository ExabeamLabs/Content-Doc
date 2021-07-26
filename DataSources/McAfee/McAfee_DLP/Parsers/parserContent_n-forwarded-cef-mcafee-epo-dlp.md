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
      """\sshost=({src_host}[^\s]{1,2000})""",
      """\|McAfee\|ESM\|[^\|]{1,2000}\|359-({signature_id}[^\|]{1,2000})""",
      """\seventId=({alert_id}[^\s]{1,2000})\s[^\s]{1,2000}?=""",
      """\snitroThreat_Name=({alert_name}.+?)\s[^\s]{1,2000}?=""",
      """\snitroObject_Type=({alert_type}.+?)\s[^\s]{1,2000}?=""",
      """\sduser=([^\\=]{1,2000}?\\)?({user}.+?)\s[^\s]{1,2000}?=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\snitroProcess_Name=({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))\s[^\s]{1,2000}="""
    ]
    DupFields = ["directory->process_directory"]
  }
```