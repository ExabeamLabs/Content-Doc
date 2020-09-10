#### Parser Content
```Java
{
Name = s-5141-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EventID=5141""", """A directory service object was deleted""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}A directory service object was deleted)""",
    """DetectTime=({time_created}.+?)\s+\w+=""",
    """ComputerName=({host}[\w.\-]+)""",
    """EventID=({event_code}\w+)""",
    """Account Name=({user}.+?)\s+""",
    """Account Domain=({domain}.+?)\s""",
    """Logon ID=({logon_id}[^\s]+)\s""",
    """Object:Class=({object_class}.+?)\s""",
    """Object:DN=({object_dn}.+?)\s*Object:GUID=""",
    """Object:DN=.+?({object_ou}OU.+?)\s*Object:GUID"""
  ]
  DupFields = [ "host->dest_host" ]
}
```