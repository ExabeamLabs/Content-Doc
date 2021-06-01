#### Parser Content
```Java
{
Name = ad-audit-4663-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4663"
  TimeFormat = "epoch_sec"
  Conditions = [ """EVENT_NUMBER = 4663""","""An object was deleted"""]
  Fields = [
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """({event_name}An object was deleted)""",
    """OBJECT_NAME\s{0,100}=\s{0,100}(({file_path}({file_parent}(\w:)?(?:[^:\]]{1,2000})?[\\\/])?({file_name}[^\\\/"\]]{1,2000}?)))\s{0,100}\]""",
    """\sFILE_TYPE\s{0,100}=\s{0,100}\.({file_ext}\w+)\s{0,100}\]""",
    """LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^]]{1,2000}?)\s{0,100}\]""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^]]{1,2000}?)\s{0,100}\]""",
    """ACCESSES\s{0,100}=\s{0,100}({accesses}[^]]{1,2000}?)\s{0,100}\]""",
    """ACCESS_MASK\s{0,100}=\s{0,100}({access_mask}[^]]{1,2000}?)\s{0,100}]""",
    """PROCESS_ID\s{0,100}=\s{0,100}(null|({process_id}[^]]{1,2000}?))\s{0,100}\]""",
    """\WPROCESS_NAME\s{0,100}=\s{0,100}(|null|({process}({directory}(\w:)?(?:[^:\]]{1,2000})?[\\\/])?({process_name}[^\\\/"\]]{1,2000}?)))\s{0,100}\]""",
    """USERNAME\s{0,100}=\s{0,100}(({user}[^]]{1,2000}?))\s{0,100}\]""",
    """USER_SID\s{0,100}=\s{0,100}(({user_sid}[^]]{1,2000}?))\s{0,100}\]""",	
  ]
  DupFields = [ "host->dest_host" ,"directory->process_directory"]
}
```