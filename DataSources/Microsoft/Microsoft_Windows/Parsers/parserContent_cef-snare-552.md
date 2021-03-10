#### Parser Content
```Java
{
Name = cef-snare-552
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-account-switch"
    TimeFormat = "epoch"
    Conditions = ["|Snare|", "|Security:552|Logon attempt using explicit credentials|"]
    Fields = [
      """({event_name}Logon attempt using explicit credentials)""",
      """({event_code}552)"""
      """rt=({time}\d+)""",
      """ahost=({host}[^\s]+)"""
      """dvchost=({dest_host}[^\s]+)""",
      """duser=({account}[\w\-\.]+(?:\w+)?\$?)\s+\w+=""",
      """suser=({user}[\w\-\.\s]+(?:\w+)?\$?)\s+\w+="""
      """dntdom=({domain}.+?)\s+\w+=""",
    ]
  }
```