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
      """\|McAfee\|[^|]+?\|[^|]+?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """rt=({time}\d{1,100})""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """deviceExternalId=({host}[^\s]+)""",
      """shost=({dest_host}[^\s]+)""",
      """src=({src_ip}[a-fA-F:\d.]+)""",
      """duser=({account}[\w\-\.]+(?:\w+)?\$?)\s{1,100}suser""",
      """suser=({user}[\w\-\.\s]+(?:\w+)?\$?)\s{1,100}nitroSecurity"""
      """sntdom=({domain}.+?)\s{1,100}shost""",
      """nitroSecurity_ID=({user_sid}[^\s]+)""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)""",
      """nitroAppID=\s{0,100}(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s{1,100}\w+="""
    ]
    DupFields = ["directory->process_directory"]
  }
```