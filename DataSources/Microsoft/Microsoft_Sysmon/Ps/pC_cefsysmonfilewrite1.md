#### Parser Content
```Java
{
Name = cef-sysmon-file-write-1
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|SysmonTask-SYSMON_FILE_CREATE|File created|""" ]

cef-sysmon-file-write = {
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """({host}\S+) CEF:""",
    """\Wdvc=({host}[A-Fa-f:\d]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\WeventId=({event_code}\d{1,100})""",
    """\WcategoryOutcome=\/({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wdproc=({file_path}({file_parent}.*?)({file_name}[^\\.]{1,2000}(\.({file_ext}[^\\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """\Wdproc=({process}({directory}.*?)({process_name}[^\\]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wfname=.+?USERS\\+({user}[^\s\\]{1,2000})""",
    """\Wfname=({file_path}({file_parent}.*?)({file_name}[^\\.]{1,2000}(\.({file_ext}[^\\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """\Wcs6=\{({process_guid}[^\}]{1,2000})""",
    """\Wdpid=({pid}\d{1,100})""",
    """\Wcs1=({object}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory", "host->dest_host" 
}
```