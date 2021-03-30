#### Parser Content
```Java
{
Name = n-forwarded-cef-552
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-account-switch"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-21100552"]
    Fields = [
      """({event_name}Logon attempt using explicit credentials)""",
      """\|McAfee\|.+?\|43-21100({event_code}\d+)(0|1)\|""",
      """rt=({time}\d+)""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """shost=({dest_host}[^\s]+)""",
      """duser=({account}[\w\-\.]+(?:\w+)?\$?)\s+suser""",
      """suser=({user}[\w\-\.\s]+(?:\w+)?\$?)\s+nitroSource"""
      """sntdom=({domain}.+?)\s+shost""",
      """nitroSource_Logon_ID=\([^,]+,({logon_id}[^\)]+)"""
    ]
  }
```