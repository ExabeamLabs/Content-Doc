#### Parser Content
```Java
{
Name = cef-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-failed-logon"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4625|"""]
    Fields = [
      """({event_name}An account failed to log on)""",
      """\sexternalId=({event_code}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}[a-fA-F:\d.]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sduser=({user}.+?)\s{1,100}\w+=""",
      """\sdntdom=({domain}.+?)\s\w+=""",
      """Security_,ID=({user_sid}[^\s]+)""",
      """\ssrc=(?:-|({src_ip}[\w:.]+))\s{1,100}\w+=""",
      """\scn1=({logon_type}\d{1,100})""",
      """\scs5=({auth_package}[^\s]+)""",
      """\sdeviceProcessName=({auth_process}[^\s]+)""",
      """Sub_,Status=({result_code}[^\s]+)""",
      """Account locked out.+?flexString1=({result_code}[^\s]+)"""
      """Key_,Length=({key_length}\d{1,100})"""
    ]
    DupFields = ["host->dest_host"]
  }
```