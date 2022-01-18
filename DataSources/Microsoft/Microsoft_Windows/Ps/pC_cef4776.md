#### Parser Content
```Java
{
Name = cef-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-4776"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4776"""]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """({event_code}4776)""",
      """\srt=({time}\d{1,100})""",
      """\sshost=({dest_host}[^\s]{1,2000})""",
      """src=({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """dvchost=(?!(?:[A-Fa-f:\d.]{1,2000}))[^\s.]{1,2000}(\.({domain}[^\s.]{1,2000})[^\s]{0,2000})"""
      """\sduser=({user}.+?)(@({domain}[^\s.]{1,2000})[^\s]{0,2000})?\s{1,100}\w+=""",
      """\scs4=({result_code}\w+)""",
      """dvc=({host}[^\s]{1,2000})""",
      """dvchost=({host}[^\s]{1,2000})""",
    ]
  

}
```