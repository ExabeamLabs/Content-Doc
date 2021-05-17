#### Parser Content
```Java
{
Name = raw-5140-1
   Vendor = Microsoft
   Product = Microsoft Windows
   Lms = Direct
   DataType = "share-access"
   TimeFormat = "yyyy-MM-dd HH:mm:ss"
   Conditions = [  """A network share object was accessed""", """Account Name=""", """EventID=5140""" ]
   Fields = [
      """({event_name}A network share object was accessed)""",
      """({event_code}5140)""",
      """ComputerName=({host}[^\s]{1,2000})""",
      """DetectTime=({time}\d\d\d\d-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})""",
      """Logon ID=\s{0,100}({logon_id}\S+)""",
      """Account Name=\s{0,100}({user}[^\s]{1,2000})""",
      """Account Domain=\s{0,100}({domain}[^\s]{1,2000})""",
      """Object Type=\s{0,100}({file_type}[^\s]{1,2000})""",
      """Source Address=\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """({accesses}Read)""",
      """Share Name=\s{0,100}[\\\*]{0,2000}({share_name}[^\s]{1,2000})\s{0,100}Share""",
      """Share Path=\s{0,100}[\\\?]{0,2000}(\s{0,100}|({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]{1,2000}?)))\\?)\s{0,100}Access Request Information:"""
   ]
    DupFields = ["host->dest_host"]
 }
```