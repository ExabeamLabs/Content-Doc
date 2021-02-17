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
      """ComputerName=({host}[^\s]+)""",
      """DetectTime=({time}\d\d\d\d-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})""",
      """Logon ID=\s*({logon_id}\S+)""",
      """Account Name=\s*({user}[^\s]+)""",
      """Account Domain=\s*({domain}[^\s]+)""",
      """Object Type=\s*({file_type}[^\s]+)""",
      """Source Address=\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """({accesses}Read)""",
      """Share Name=\s*[\\\*]*({share_name}[^\s]+)\s*Share""",
      """Share Path=\s*[\\\?]*(\s*|({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]+?)))\\?)\s*Access Request Information:"""
   ]
    DupFields = ["host->dest_host"]
 }
```