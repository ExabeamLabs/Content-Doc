#### Parser Content
```Java
{
Name = cef-syslog-sharepoint-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|||""", """cat=SharePointFileOperation""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\scs5=({app}.+?)\s{1,100}\w+=""",
    """\sact=({accesses}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuid=({user}[^@]{1,2000})(@({domain}[^\s]{1,2000}))?\s{1,100}\w+=""",
    """\sfilePath=({file_path}.+?)\s{1,100}\w+=""",
    """\sfilePath=(?: |({file_parent}[^=]{1,2000})[\\\/]{1,2000}[^\\\/=]{1,2000})\s{1,100}\w+=""",
    """\sfileType=({file_type}.+?)\s{1,100}\w+=""",
    """\soldFileName=({file_name}.+?)\s{1,100}\w+=""",
    """\soldFileType=({file_ext}.+?)\s{1,100}\w+=""",
  ]
  DupFields = [ "accesses->event_code" ]
}
```