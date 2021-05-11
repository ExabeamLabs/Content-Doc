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
      """\sshost=({src_host}[^\s]+)""",
      """\snitroObject_Type=({activity}.+?)\s[^\s]+?=""",
      """\snitroThreat_Name=({activity_details}.+?)\s[^\s]+?=""",
      """\sduser=([^\\=]+?\\)?({user}.+?)\s[^\s]+?=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\snitroProcess_Name=({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+))\s[^\s]+="""
    ]
    DupFields = ["directory->process_directory"]
  }
```