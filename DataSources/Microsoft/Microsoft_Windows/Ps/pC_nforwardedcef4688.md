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
      """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """\srt=({time}\d{1,100})""",
      """shost=({host}[^\s]{1,2000})""",
      """sntdom=({domain}[^\s]{1,2000})""",
      """suser=({user}.+?)\s{1,100}\w+=""",      
      """nitroProcess_Name=({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))\s{1,100}\w+=""",
      """nitroProcess_Name=({path}.+?)\s{1,100}\w+=""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)"""
    ]
    DupFields=[ "host->dest_host","directory->process_directory" ]
  }
```