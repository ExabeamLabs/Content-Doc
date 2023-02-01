#### Parser Content
```Java
{
Name = cef-5136
    Vendor = Microsoft
    Product = Windows
    Lms = ArcSight
    DataType = "windows-ds-access"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """Microsoft-Windows-Security-Auditing:5136"""]
    Fields = [
      """({event_name}A directory service object was modified)""",
      """({event_code}5136)""",
      """\srt=({time}\d{13})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """categoryOutcome=\/?({outcome}[^=]{1,2000})\s\w+=""",
      """dhost=({dest_host}[\w\-.]{1,2000})""",
      """dst=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
      """duser=({user}[^=]{1,2000})\s\w+=""",
      """dntdom=({domain}[^\s]{1,2000})""",
      """fileType=({object_type}[^=]{1,2000})\s\w+=""",
      """cs5=({object_class}[^=]{1,2000})\s\w+=""",
      """cs6=({object_dn}.{1,2000}?)\s\w+="""
    ]
  

}
```