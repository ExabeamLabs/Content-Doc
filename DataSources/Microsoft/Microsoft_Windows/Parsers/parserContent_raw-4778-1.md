#### Parser Content
```Java
{
Name = raw-4778-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4778"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """EventCategory=""", """EventID=4778""", """Microsoft-Windows-Security-Auditing""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EventSource=({event_name}[^\s]{1,2000})\s""",
      """Description=({event_name}[^\.]{1,2000}).""",
      """({event_code}4778)""",
      """WindowsVersion=({os_version}.+?)\s{0,100}\w+=""",
      """({time_created}\d{1,4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2})\s""",
      """User=(null|({user}.+?))\s{0,100}\w+=""",
      """Client Address=({src_ip}[^"]{1,2000})""""
      """Client Name=({src_host}[^\s]{1,2000})\s"""
      """Account Name=({user}[^\s]{1,2000})\s"""
      """Message=({additional_info}[^\.]{1,2000})."""
      """Account Domain=({domain}[^\s]{1,2000})\s"""
      """Logon ID=({logon_id}[^\s]{1,2000})\s"""
      """ComputerName=({host}[^\s]{1,2000})\s""",
      """EventType=({outcome}.+?)\s{0,100}\w+=""",
      """Key\[0\]=({user}[^\s]{1,2000})\s""",
      """Key\[5\]=({src_ip}[^"]{1,2000})"""",
      """Key\[4\]=({host}[^\s]{1,2000})\s""",
      """Key\[2\]=({logon_id}[^\s]{1,2000})\s""",
    ]
  }
```