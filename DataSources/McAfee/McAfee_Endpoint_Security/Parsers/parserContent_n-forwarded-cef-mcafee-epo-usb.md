#### Parser Content
```Java
{
Name = n-forwarded-cef-mcafee-epo-usb
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = NitroCefSyslog
    DataType = "usb-activity"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|ESM|""", """|359-""", """OUTGOING_FS_REMOVABLE_STORAGE""", """EVDNC|MON|OFF""" ]
    Fields = [ 
      """\send=({time}\d{1,100})""",
      """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sshost=({src_host}[^\s]{1,2000})""",
      """\snitroObject_Type=({activity}.+?)\s[^\s]{1,2000}?=""",
      """\snitroThreat_Name=({activity_details}.+?)\s[^\s]{1,2000}?=""",
      """\sduser=([^\\=]{1,2000}?\\)?({user}.+?)\s[^\s]{1,2000}?=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\snitroProcess_Name=({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}))\s[^\s]{1,2000}="""
    ]
    DupFields = ["directory->process_directory"]
  }
```