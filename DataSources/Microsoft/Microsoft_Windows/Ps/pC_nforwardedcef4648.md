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
      """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """rt=({time}\d{1,100})""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]{1,2000})""",
      """deviceExternalId=({host}[^\s]{1,2000})""",
      """shost=({dest_host}[^\s]{1,2000})""",
      """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
      """duser=({account}[\w\-\.]{1,2000}(?:\w+)?\$?)\s{1,100}suser""",
      """suser=({user}[\w\-\.\s]{1,2000}(?:\w+)?\$?)\s{1,100}nitroSecurity"""
      """sntdom=({domain}.+?)\s{1,100}shost""",
      """nitroSecurity_ID=({user_sid}[^\s]{1,2000})""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)""",
      """nitroAppID=\s{0,100}(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))\s{1,100}\w+="""
    ]
    DupFields = ["directory->process_directory"]
  

}
```