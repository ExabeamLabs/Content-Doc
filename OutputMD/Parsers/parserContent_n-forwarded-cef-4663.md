#### Parser Content
```Java
{
Name = n-forwarded-cef-4663
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-4663"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ "|McAfee|ESM", "43-26304663"]
    Fields = [ """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """({event_name}An attempt was made to access an object)""",
      """\srt=({time}\d+)""",
      """shost=({host}[^\s]+)""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",
      """nitroDestination_Filename=({file_path}.+?)\s+\w+=""",
      """nitroDestination_Filename=.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:\s]+)?|[^\\:\s]+)\s+\w+=""",
      """nitroDestination_Filename=({file_parent}.+?)\\(?:[^\\]+?)\s+\w+=""",
      """nitroSecurity_ID=({user_sid}[^\s]+)""",
      """nitroSource_Logon_ID=({logon_id}[^\s]+)""",
      """nitroAccess_Privileges=\d+ - ({accesses}[^\r\n]+)\s+""",
      """nitroAccess_mask=({access_mask}\w+)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```