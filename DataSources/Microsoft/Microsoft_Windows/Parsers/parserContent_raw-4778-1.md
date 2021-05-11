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
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EventSource=({event_name}[^\s]+)\s""",
      """Description=({event_name}[^\.]+).""",
      """({event_code}4778)""",
      """WindowsVersion=({os_version}.+?)\s{0,100}\w+=""",
      """({time_created}\d{1,4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2})\s""",
      """User=(null|({user}.+?))\s{0,100}\w+=""",
      """Client Address=({src_ip}[^"]+)""""
      """Client Name=({src_host}[^\s]+)\s"""
      """Account Name=({user}[^\s]+)\s"""
      """Message=({additional_info}[^\.]+)."""
      """Account Domain=({domain}[^\s]+)\s"""
      """Logon ID=({logon_id}[^\s]+)\s"""
      """ComputerName=({host}[^\s]+)\s""",
      """EventType=({outcome}.+?)\s{0,100}\w+=""",
      """Key\[0\]=({user}[^\s]+)\s""",
      """Key\[5\]=({src_ip}[^"]+)"""",
      """Key\[4\]=({host}[^\s]+)\s""",
      """Key\[2\]=({logon_id}[^\s]+)\s""",
    ]
  }
```