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
      """rt=({time}\d{1,100})""",
      """ahost=({host}[^\s]{1,2000})"""
      """dvchost=({dest_host}[^\s]{1,2000})""",
      """duser=({account}[\w\-\.]{1,2000}(?:\w+)?\$?)\s{1,100}\w+=""",
      """suser=({user}[\w\-\.\s]{1,2000}(?:\w+)?\$?)\s{1,100}\w+="""
      """dntdom=({domain}.+?)\s{1,100}\w+=""",
      """OriginalAgentAddress=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
      """dvc=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    ]
  }
```