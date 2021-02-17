#### Parser Content
```Java
{
Name = n-forwarded-cef-4688
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ "|McAfee|ESM", "43-26304688"]
    Fields = [ 
      """({event_name}A new process has been created)""",
      """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """\srt=({time}\d+)""",
      """shost=({host}[^\s]+)""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",      """nitroProcess_Name=({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s+\w+=""",
      """nitroProcess_Name=({path}.+?)\s+\w+=""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)"""
    ]
    DupFields=[ "host->dest_host","directory->process_directory" ]
  }
```