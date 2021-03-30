#### Parser Content
```Java
{
Name = cef-syslog-sharepoint-activity
  Vendor = Microsoft
  Product =  Office 365
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|||""", """cat=SharePointFileOperation""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """\scs5=({app}.+?)\s+\w+=""",
    """\sact=({accesses}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuid=({user}[^@]+)(@({domain}[^\s]+))?\s+\w+=""",
    """\sfilePath=({file_path}.+?)\s+\w+=""",
    """\sfilePath=(?: |({file_parent}[^=]+)[\\\/]+[^\\\/=]+)\s+\w+=""",
    """\sfileType=({file_type}.+?)\s+\w+=""",
    """\soldFileName=({file_name}.+?)\s+\w+=""",
    """\soldFileType=({file_ext}.+?)\s+\w+=""",
  ]
  DupFields = [ "accesses->event_code" ]
}
```