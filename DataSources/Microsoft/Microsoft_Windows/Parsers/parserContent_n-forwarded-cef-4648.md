#### Parser Content
```Java
{
Name = n-forwarded-cef-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-account-switch"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-26304648"]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """rt=({time}\d+)""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """deviceExternalId=({host}[^\s]+)""",
      """shost=({dest_host}[^\s]+)""",
      """src=({src_ip}[a-fA-F:\d.]+)""",
      """duser=({account}[\w\-\.]+(?:\w+)?\$?)\s+suser""",
      """suser=({user}[\w\-\.\s]+(?:\w+)?\$?)\s+nitroSecurity"""
      """sntdom=({domain}.+?)\s+shost""",
      """nitroSecurity_ID=({user_sid}[^\s]+)""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)""",
      """nitroAppID=\s*(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s+\w+="""
    ]
    DupFields = ["directory->process_directory"]
  }
```